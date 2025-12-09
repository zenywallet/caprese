# Copyright (c) 2022 zenywallet

import std/nativesockets
import std/posix
when defined(linux):
  import std/epoll
elif defined(openbsd):
  import std/kqueue
import std/strutils
import std/options
import bytes
import arraylib
import queue
import ptlock
import server_types

const ENABLE_KEEPALIVE = false
const ENABLE_TCP_NODELAY = true
const PROXY_EVENTS_SIZE = 10

type
  RecvCallback* = proc(originalClientId: ClientId, buf: ptr UncheckedArray[byte], size: int) {.gcsafe.}

  AbortCallback* = proc() {.gcsafe.}

  ProxyParams* = object
    abortCallback*: AbortCallback

  ProxyObj* = object
    sock*: SocketHandle
    originalClientId*: ClientId
    recvCallback*: RecvCallback
    sendBuf*: ptr UncheckedArray[byte]
    sendBufSize*: int
    lock*: RWLock

  Proxy* = ptr ProxyObj

  ProxyError* = object of CatchableError

var active = false
var evfd: cint = -1

template errorException(x: varargs[string, `$`]) =
  var msg = join(x)
  echo msg
  raise newException(ProxyError, msg)

template at(p: ptr UncheckedArray[byte] or string or seq[byte], pos: int): ptr UncheckedArray[byte] =
  cast[ptr UncheckedArray[byte]](addr p[pos])

proc newProxy*(hostname: string, port: Port): Proxy =
  var aiList: ptr AddrInfo
  try:
    aiList = getAddrInfo(hostname, port, Domain.AF_UNSPEC)
  except:
    errorException "error: getaddrinfo hostname=", hostname, " port=", port, " errno=", errno
  let domain = aiList.ai_family.toKnownDomain.get
  let sock = createNativeSocket(domain)
  when ENABLE_KEEPALIVE:
    sock.setSockOptInt(SOL_SOCKET, SO_KEEPALIVE, 1)
  when ENABLE_TCP_NODELAY:
    sock.setSockOptInt(Protocol.IPPROTO_TCP.int, TCP_NODELAY, 1)
  sock.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1) # local proxy only
  # bind
  sock.setBlocking(false)
  discard sock.connect(aiList.ai_addr, aiList.ai_addrlen.SockLen)
  freeaddrinfo(aiList)
  var p = cast[Proxy](allocShared0(sizeof(ProxyObj)))
  p.sock = sock
  rwlockInit(p.lock)
  result = p

proc newProxy*(unixDomainSockFile: string): Proxy =
  let sock = socket(Domain.AF_UNIX.cint, posix.SOCK_STREAM, 0)
  when ENABLE_KEEPALIVE:
    sock.setSockOptInt(SOL_SOCKET, SO_KEEPALIVE, 1)
  sock.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1) # local proxy only
  # bind
  sock.setBlocking(false)
  var sa: Sockaddr_un
  sa.sun_family = Domain.AF_UNIX.TSa_Family
  if unixDomainSockFile.len > sa.sun_path.len:
    errorException "error: unix domain socket file is too long"
  copyMem(addr sa.sun_path[0], unsafeAddr unixDomainSockFile[0], unixDomainSockFile.len)
  discard sock.connect(cast[ptr SockAddr](addr sa), sizeof(sa).SockLen)
  var p = cast[Proxy](allocShared0(sizeof(ProxyObj)))
  p.sock = sock
  rwlockInit(p.lock)
  result = p

proc free*(proxy: Proxy) =
  var sock {.noInit.}: SocketHandle
  withWriteLock proxy.lock:
    sock = proxy.sock
    if sock == osInvalidSocket: return
    proxy.sock = osInvalidSocket
  sock.close()
  if not proxy.sendBuf.isNil:
    proxy.sendBuf.deallocShared()
  rwlockDestroy(proxy.lock)
  proxy.deallocShared()

proc shutdown*(proxy: Proxy): bool {.discardable.} =
  var retShutdown = proxy.sock.shutdown(SHUT_RD)
  if retShutdown != 0:
    echo "error: shutdown ret=", retShutdown, " errno=", errno
    result = false
  else:
    result = true

proc setRecvCallback*(proxy: Proxy, recvCallback: RecvCallback, evOut: static bool = false) {.inline.} =
  proxy.recvCallback = recvCallback

  var ev: EpollEvent
  when evOut:
    ev.events = EPOLLIN or EPOLLRDHUP or EPOLLOUT
  else:
    ev.events = EPOLLIN or EPOLLRDHUP
  ev.data.u64 = cast[uint64](proxy)
  var ret = epoll_ctl(evfd, EPOLL_CTL_ADD, proxy.sock.cint, addr ev)
  if ret < 0:
    errorException "error: EPOLL_CTL_ADD ret=", ret, " errno=", errno

proc reallocClientBuf(buf: ptr UncheckedArray[byte], size: int): ptr UncheckedArray[byte] =
  result = cast[ptr UncheckedArray[byte]](reallocShared(buf, size))

proc addSendBuf(proxy: Proxy, data: ptr UncheckedArray[byte], size: int) =
  var nextSize = proxy.sendBufSize + size
  proxy.sendBuf = reallocClientBuf(proxy.sendBuf, nextSize)
  copyMem(addr proxy.sendBuf[proxy.sendBufSize], data, size)
  proxy.sendBufSize = nextSize

proc send*(proxy: Proxy, data: ptr UncheckedArray[byte], size: int, evMod: static bool = true): SendResult =
  withWriteLock proxy.lock:
    if not proxy.sendBuf.isNil:
      proxy.addSendBuf(data, size)
      return SendResult.Pending

    var pos = 0
    var left = size
    while true:
      var d = data.at(pos)
      let sendRet = proxy.sock.send(cast[cstring](d), left.cint, 0'i32)
      if sendRet > 0:
        left = left - sendRet
        if left > 0:
          pos = pos + sendRet
          continue
        return SendResult.Success
      elif sendRet < 0:
        if errno == EAGAIN or errno == EWOULDBLOCK:
          if proxy.sendBuf.isNil:
            proxy.addSendBuf(d, left)
            when evMod:
              var ev: EpollEvent
              ev.events = EPOLLIN or EPOLLRDHUP or EPOLLOUT
              ev.data.u64 = cast[uint64](proxy)
              var ret = epoll_ctl(evfd, EPOLL_CTL_MOD, proxy.sock.cint, addr ev)
              if ret < 0:
                errorException "error: EPOLL_CTL_MOD ret=", ret, " errno=", errno
          else:
            proxy.addSendBuf(d, left)
          return SendResult.Pending
        elif errno == EINTR:
          continue
        return SendResult.Error
      else:
        return SendResult.None

proc sendFlush(proxy: Proxy): SendResult =
  withWriteLock proxy.lock:
    if proxy.sendBuf.isNil:
      return SendResult.None

    var pos = 0
    var left = proxy.sendBufSize
    while true:
      var d = proxy.sendBuf.at(pos)
      let sendRet = proxy.sock.send(cast[cstring](d), left.cint, 0'i32)
      if sendRet > 0:
        left = left - sendRet
        if left > 0:
          pos = pos + sendRet
          continue
        proxy.sendBufSize = 0
        proxy.sendBuf.deallocShared()
        proxy.sendBuf = nil
        return SendResult.Success
      elif sendRet < 0:
        if errno == EAGAIN or errno == EWOULDBLOCK:
          copyMem(addr proxy.sendBuf[0], d, left)
          proxy.sendBufSize = left
          return SendResult.Pending
        elif errno == EINTR:
          continue
        return SendResult.Error
      else:
        return SendResult.None

var abortSock: SocketHandle = osInvalidSocket

proc proxyDispatcher(params: ProxyParams) {.thread.} =
  try:
    var tcp_rmem = abortSock.getSockOptInt(SOL_SOCKET, SO_RCVBUF)

    var buf = newSeq[byte](tcp_rmem)
    var toBeFreed = newArrayOfCap[Proxy](PROXY_EVENTS_SIZE)
    var nfd: cint
    var nfdCond: bool
    var evIdx: int = 0
    template nextEv() =
      inc(evIdx); if evIdx >= nfd: evIdx = 0; break

    evfd = epoll_create1(O_CLOEXEC)
    if evfd < 0:
      errorException "error: evfd=", evfd, " errno=", errno

    var proxyEvents: array[PROXY_EVENTS_SIZE, EpollEvent]
    while true:
      nfd = epoll_wait(evfd, cast[ptr EpollEvent](addr proxyEvents),
                      PROXY_EVENTS_SIZE.cint, -1.cint)
      nfdCond = likely(nfd > 0)
      if nfdCond:
        if not active:
          break

        while true:
          let proxy = cast[Proxy](proxyEvents[evIdx].data.u64)
          if (proxyEvents[evIdx].events.uint32 and EPOLLOUT.uint32) > 0:
            var retFlush = proxy.sendFlush()
            if retFlush == SendResult.Pending:
              nextEv()
              continue
            var ev: EpollEvent
            ev.events = EPOLLIN or EPOLLRDHUP
            ev.data.u64 = cast[uint64](proxy)
            var ret = epoll_ctl(evfd, EPOLL_CTL_MOD, proxy.sock.cint, addr ev)
            if ret < 0:
              proxy.recvCallback(proxy.originalClientId, nil, 0)
              toBeFreed.add(proxy)
              echo "error: EPOLL_CTL_MOD evfd=", ret, " errno=", errno
              nextEv()
              continue

          if (proxyEvents[evIdx].events.uint32 and EPOLLIN.uint32) > 0:
            var retLen = proxy.sock.recv(addr buf[0], buf.len, 0'i32)
            if retLen > 0:
              proxy.recvCallback(proxy.originalClientId, buf.at(0), retLen)
            elif retLen == 0:
              proxy.recvCallback(proxy.originalClientId, nil, retLen)
              toBeFreed.add(proxy)
            else: # retLen < 0
              if errno != EAGAIN and errno != EWOULDBLOCK and errno != EINTR:
                proxy.recvCallback(proxy.originalClientId, nil, retLen)
                toBeFreed.add(proxy)
          nextEv()

        if toBeFreed.len > 0:
          for p in toBeFreed: p.free()
          toBeFreed.clear()

      else:
        if (nfd < 0 and errno != EINTR) or nfd == 0:
          errorException "error: epoll_wait ret=", nfd, " errno=", errno
        else:
          echo "info: epoll_wait ret=", nfd, " errno=", errno

  except:
    let e = getCurrentException()
    echo e.name, ": ", e.msg
    params.abortCallback()

proc proxyManager*(params: ProxyParams): Thread[ProxyParams] =
  active = true
  abortSock = createNativeSocket()
  createThread(result, proxyDispatcher, params)

proc quitProxyManager*(proxyThread: Thread[ProxyParams]) =
  active = false
  var ev: EpollEvent
  ev.events = EPOLLRDHUP
  var ret = epoll_ctl(evfd, EPOLL_CTL_ADD, abortSock.cint, addr ev)
  if ret < 0:
    errorException "error: EPOLL_CTL_ADD evfd=", ret, " errno=", errno
  proxyThread.joinThread()
  abortSock.close()


when isMainModule:
  import os

  var params: ProxyParams
  params.abortCallback = proc() =
    errorException "error: proxy dispatcher"

  var proxyThread = proxyManager(params)

  sleep(1000)

  try:
    let proxy = newProxy("localhost", 8000.Port)
    try:
      proxy.originalClientId = 1

      proc proxyRecvCallback(originalClientId: ClientId, buf: ptr UncheckedArray[byte], size: int) =
        echo "recvCallback originalClientId=", originalClientId, " size=", size
        if size <= 0:
          proxy.free()
        else:
          echo buf.toString(size)

      proxy.setRecvCallback(proxyRecvCallback)

      var getMsg = "GET /test.html HTTP/1.1\c\L" &
                  "Host: localhost:8000\c\L" &
                  "\c\L\c\L"

      var sendRet = proxy.send(getMsg.at(0), getMsg.len)
      echo "send ret=", sendRet
      if sendRet == SendResult.Error:
        errorException "error: send failed"

      sleep(3000)
      proxy.shutdown()

    except:
      echo "proxy free"
      proxy.free()
  except:
    let e = getCurrentException()
    echo e.name, ": ", e.msg

  quitProxyManager(proxyThread)

  # Some problems with free in case of connection errors
  # Fundamental structural changes may be needed
  # The current implementation in server.nim does not cause the problem,
  # but do not deviate from that method.
