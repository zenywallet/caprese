# Copyright (c) 2022 zenywallet

import std/nativesockets
import std/posix
import std/epoll
import std/strutils
import bytes
import queue
import ptlock
import server_types

const ENABLE_KEEPALIVE = false
const ENABLE_TCP_NODELAY = true
const EPOLL_EVENTS_SIZE = 10

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
    lock*: int # RWLock workaround

  Proxy* = ptr ProxyObj

  ProxyError* = object of CatchableError

var active = true
var epfd: cint = -1
var proxyDispatcherThread: Thread[ProxyParams]

template errorException(x: varargs[string, `$`]) =
  var msg = join(x)
  echo msg
  raise newException(ProxyError, msg)

template at(p: ptr UncheckedArray[byte] or string or seq[byte], pos: int): ptr UncheckedArray[byte] =
  cast[ptr UncheckedArray[byte]](addr p[pos])

template toRWLock(lock: int): RWLock = cast[ptr RWLock](unsafeAddr lock)[]

proc newProxy*(hostname: string, port: Port): Proxy =
  var sock = createNativeSocket()
  when ENABLE_KEEPALIVE:
    sock.setSockOptInt(SOL_SOCKET, SO_KEEPALIVE, 1)
  when ENABLE_TCP_NODELAY:
    sock.setSockOptInt(Protocol.IPPROTO_TCP.int, TCP_NODELAY, 1)
  sock.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1) # local proxy only
  # bind
  sock.setBlocking(false)
  var aiList: ptr AddrInfo
  try:
    aiList = getAddrInfo(hostname, port, Domain.AF_INET)
  except:
    sock.close()
    errorException "error: getaddrinfo hostname=", hostname, " port=", port, " errno=", errno
  discard sock.connect(aiList.ai_addr, aiList.ai_addrlen.SockLen)
  freeaddrinfo(aiList)
  var p = cast[Proxy](allocShared0(sizeof(ProxyObj)))
  p.sock = sock
  rwlockInit(p.lock.toRWLock)
  result = p

proc free*(proxy: Proxy) =
  var sock = proxy.sock
  withWriteLock proxy.lock.toRWLock:
    if sock == osInvalidSocket: return
    proxy.sock = osInvalidSocket
  var ret = epoll_ctl(epfd, EPOLL_CTL_DEL, sock.cint, nil)
  if ret < 0:
    echo "error: EPOLL_CTL_DEL ret=", ret, " errno=", errno
  sock.close()
  rwlockDestroy(proxy.lock.toRWLock)
  proxy.deallocShared()

proc shutdown*(proxy: Proxy): bool {.discardable.} =
  var retShutdown = proxy.sock.shutdown(SHUT_RD)
  if retShutdown != 0:
    echo "error: shutdown ret=", retShutdown, " errno=", errno
    result = false
  else:
    result = true

proc setRecvCallback*(proxy: Proxy, recvCallback: RecvCallback) {.inline.} =
  proxy.recvCallback = recvCallback

  var ev: EpollEvent
  ev.events = EPOLLIN or EPOLLRDHUP
  ev.data.u64 = cast[uint64](proxy)
  var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, proxy.sock.cint, addr ev)
  if ret < 0:
    errorException "error: EPOLL_CTL_ADD ret=", ret, " errno=", errno

proc reallocClientBuf(buf: ptr UncheckedArray[byte], size: int): ptr UncheckedArray[byte] =
  result = cast[ptr UncheckedArray[byte]](reallocShared(buf, size))

proc addSendBuf(proxy: Proxy, data: ptr UncheckedArray[byte], size: int) =
  var nextSize = proxy.sendBufSize + size
  proxy.sendBuf = reallocClientBuf(proxy.sendBuf, nextSize)
  copyMem(addr proxy.sendBuf[proxy.sendBufSize], data, size)
  proxy.sendBufSize = nextSize

proc send*(proxy: Proxy, data: ptr UncheckedArray[byte], size: int): SendResult =
  withWriteLock proxy.lock.toRWLock:
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
            var ev: EpollEvent
            ev.events = EPOLLIN or EPOLLRDHUP or EPOLLOUT
            ev.data.u64 = cast[uint64](proxy)
            var ret = epoll_ctl(epfd, EPOLL_CTL_MOD, proxy.sock.cint, addr ev)
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
  withWriteLock proxy.lock.toRWLock:
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
    abortSock = createNativeSocket()
    var tcp_rmem = abortSock.getSockOptInt(SOL_SOCKET, SO_RCVBUF)

    var buf = newSeq[byte](tcp_rmem)

    epfd = epoll_create1(O_CLOEXEC)
    if epfd < 0:
      errorException "error: epfd=", epfd, " errno=", errno

    var epollEvents: array[EPOLL_EVENTS_SIZE, EpollEvent]
    while true:
      var nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr epollEvents),
                          EPOLL_EVENTS_SIZE.cint, 3000.cint)
      if not active:
        break

      for i in 0..<nfd:
        let proxy = cast[Proxy](epollEvents[i].data.u64)
        if (epollEvents[i].events.int and EPOLLOUT.int) > 0:
          var retFlush = proxy.sendFlush()
          if retFlush == SendResult.Pending:
            continue
          var ev: EpollEvent
          ev.events = EPOLLIN or EPOLLRDHUP
          ev.data.u64 = cast[uint64](proxy)
          var ret = epoll_ctl(epfd, EPOLL_CTL_MOD, proxy.sock.cint, addr ev)
          if ret < 0:
            proxy.recvCallback(proxy.originalClientId, nil, 0)
            echo "error: EPOLL_CTL_MOD epfd=", ret, " errno=", errno
            continue

        if (epollEvents[i].events.int and EPOLLIN.int) > 0:
          var retLen = proxy.sock.recv(addr buf[0], buf.len, 0'i32)
          if retLen > 0:
            proxy.recvCallback(proxy.originalClientId, buf.at(0), retLen)
          elif retLen == 0:
            proxy.recvCallback(proxy.originalClientId, nil, retLen)
          else: # retLen < 0
            if errno != EAGAIN and errno != EWOULDBLOCK and errno != EINTR:
              proxy.recvCallback(proxy.originalClientId, nil, retLen)
  except:
    let e = getCurrentException()
    echo e.name, ": ", e.msg
    params.abortCallback()

proc proxyManager*(params: ProxyParams) =
  active = true
  createThread(proxyDispatcherThread, proxyDispatcher, params)

proc waitProxyManagerThread*() =
  proxyDispatcherThread.joinThread()

proc QuitProxyManager*() =
  active = false
  var ev: EpollEvent
  ev.events = EPOLLRDHUP
  var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, abortSock.cint, addr ev)
  if ret < 0:
    errorException "error: EPOLL_CTL_ADD epfd=", ret, " errno=", errno
  waitProxyManagerThread()
  abortSock.close()


when isMainModule:
  import os

  var params: ProxyParams
  params.abortCallback = proc() =
    errorException "error: proxy dispatcher"

  proxyManager(params)

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

  QuitProxyManager()

  # Some problems with free in case of connection errors
  # Fundamental structural changes may be needed
