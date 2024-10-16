# Copyright (c) 2024 zenywallet

import std/macros
import std/epoll
import std/nativesockets
import std/posix
import std/options
import std/cpuinfo
import queue2

echo "welcome server2!"

type
  AppType = enum
    AppEmpty
    AppAbort
    AppListen
    AppRoutes
    AppGet
    AppPost

var curAppId {.compileTime.} = 1
var appIdTypeList {.compileTime.} = @[AppEmpty, AppAbort]

proc newAppId(appType: static AppType): int =
  appIdTypeList.add(appType)
  inc(curAppId)
  echo "newAppId: appId=", curAppId, " appType=", appType
  echo "appIdTypeList=", appIdTypeList, " "
  curAppId

macro genAppIdEnum(): untyped =
  var appIdEnum = nnkTypeSection.newTree(
    nnkTypeDef.newTree(
      newIdentNode("AppId"),
      newEmptyNode(),
      nnkEnumTy.newTree(
        newEmptyNode()
      )
    )
  )
  for i, appType in appIdTypeList:
    appIdEnum[0][2].add(ident("AppId" & $i & "_" & $appType))
  appIdEnum

template parseServers*(serverBody: untyped) =
  macro parseBody() =
    macro addServer(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var ret = newStmtList quote do:
        echo "server ", newAppId(AppListen)
      ret.add(body)
      ret

    macro routes(routesBody: untyped): untyped =
      var ret = newStmtList quote do:
        echo "routes ", newAppId(AppRoutes)
      ret.add(routesBody)
      ret

    macro get(url: string, getBody: untyped): untyped =
      quote do:
        echo "get ", newAppId(AppGet)

    macro post(url: string, postBody: untyped): untyped =
      quote do:
        echo "post ", newAppId(AppPost)

    macro serverBodyMacro(): untyped =
      var parseServerBody = serverBody.copy()
      parseServerBody
    serverBodyMacro()

  parseBody()

  genAppIdEnum()
  for a in AppId:
    echo a

  type
    ClientObj = object
      sock: SocketHandle
      appId: AppId
      ev: EpollEvent
      ev2: EpollEvent
      sendBuf: ptr UncheckedArray[byte]
      sendPos: ptr UncheckedArray[byte]
      sendLen: int
      threadId: int
      whackaMole: bool

    Client = ptr ClientObj

  var clients = cast[ptr UncheckedArray[ClientObj]](allocShared0(sizeof(ClientObj) * cfg.clientMax))
  var clientFreePool = queue2.newQueue[Client]()

  for i in 0..<cfg.clientMax:
    var client = addr clients[i]
    client.sock = osInvalidSocket
    client.appId = AppId0_AppEmpty
    client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
    client.ev.data = cast[EpollData](client)
    client.ev2.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
    client.ev2.data = cast[EpollData](client)
    client.sendBuf = nil
    client.sendPos = nil
    client.sendLen = 0
    client.threadId = -1
    client.whackaMole = false
    var retAddFreePool = clientFreePool.add(client)
    if not retAddFreePool: raise

  var epfd: cint = epoll_create1(O_CLOEXEC)
  if epfd < 0: raise

  var sockCtl = createNativeSocket()
  if sockCtl == osInvalidSocket: raise

  var rcvBufRes: cint
  var rcvBufSize = sizeof(rcvBufRes).SockLen
  var retGetSockOpt = sockCtl.getsockopt(SOL_SOCKET.cint, SO_RCVBUF.cint, addr rcvBufRes, addr rcvBufSize)
  if retGetSockOpt < 0: raise
  var workerRecvBufSize = rcvBufRes.int
  echo "workerRecvBufSize=", workerRecvBufSize

  var abortClient: ClientObj
  abortClient.sock = sockCtl
  abortClient.appId = AppId1_AppAbort
  abortClient.ev.events = EPOLLIN
  abortClient.ev.data = cast[EpollData](addr abortClient)

  proc abortServer() =
    if epfd > 0:
      var e = epoll_ctl(epfd, EPOLL_CTL_ADD, sockCtl.cint, addr abortClient.ev)
      if e != 0:
        echo "error: abort epoll"

  onSignal(SIGINT, SIGTERM):
    echo "bye from signal ", sig
    abortServer()

  when cfg.sigPipeIgnore: signal(SIGPIPE, SIG_IGN)

  var optval = 1.cint

  proc extractBody() =
    macro addServer(bindAddress {.inject.}: string, port {.inject.}: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var appId {.inject.} = ident("AppId2_AppListen")

      var ret = newStmtList quote do:
        echo "server: ", `bindAddress`, ":", `port`

        var aiList: ptr AddrInfo = nativesockets.getAddrInfo(`bindAddress`, `port`.Port, Domain.AF_UNSPEC)
        let domain = aiList.ai_family.toKnownDomain.get
        let sock = createNativeSocket(domain)
        if sock == osInvalidSocket: raise
        if sock.setsockopt(SOL_SOCKET.cint, SO_REUSEADDR.cint, addr optval, sizeof(optval).SockLen) < 0:
          raise

        let retBind = sock.bindAddr(aiList.ai_addr, aiList.ai_addrlen.SockLen)
        if retBind < 0: raise
        freeaddrinfo(aiList)
        let retListen = sock.listen()
        if retListen < 0: raise
        sock.setBlocking(false)

        var listenObj: ClientObj
        listenObj.sock = sock
        listenObj.appId = `appId`
        listenObj.ev.events = EPOLLIN or EPOLLET
        listenObj.ev.data = cast[EpollData](addr listenObj)
        var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, addr listenObj.ev)
        if retCtl != 0: raise

      ret.add(body)
      ret

    macro routes(routesBody: untyped): untyped =
      var ret = newStmtList quote do:
        echo "routes"
      ret.add(routesBody)
      ret

    macro get(url: string, getBody: untyped): untyped =
      quote do:
        echo "get"

    macro post(url: string, postBody: untyped): untyped =
      quote do:
        echo "post"

    macro serverBodyMacro(): untyped =
      var extractServerBody = serverBody.copy()
      extractServerBody
    serverBodyMacro()

  extractBody()

  type
    ThreadArgType {.pure.} = enum
      Void
      ThreadId

    ThreadArg = object
      case argType: ThreadArgType
      of ThreadArgType.Void:
        discard
      of ThreadArgType.ThreadId:
        threadId: int

    WrapperThreadArg = tuple[threadProc: proc (arg: ThreadArg) {.thread.}, threadArg: ThreadArg]

  proc threadWrapper(wrapperArg: WrapperThreadArg) {.thread.} =
    try:
      wrapperArg.threadProc(wrapperArg.threadArg)
    except:
      let e = getCurrentException()
      echo e.name, ": ", e.msg

  template createThreadWrapper(t: var Thread[WrapperThreadArg]; threadProc: proc (arg: ThreadArg) {.thread.}; threadArg: ThreadArg) =
    createThread(t, threadWrapper, (threadProc, threadArg))

  macro appCaseBody(abortBlock {.inject.}: typed): untyped =
    var ret = nnkCaseStmt.newTree(
      nnkDotExpr.newTree(
        newIdentNode("client"),
        newIdentNode("appId")
      )
    )
    for i, appType in appIdTypeList:
      echo "#", i.AppId, " ", $appType
      var appStmt = if appType == AppAbort:
        nnkStmtList.newTree(
          nnkCall.newTree(
            newIdentNode($appType & "Macro"),
            newIdentNode($i.AppId),
            abortBlock
          )
        )
      else:
        nnkStmtList.newTree(
          nnkCall.newTree(
            newIdentNode($appType & "Macro"),
            newIdentNode($i.AppId)
          ),
          nnkCall.newTree(
            newIdentNode("nextEv")
          )
        )
      ret.add nnkOfBranch.newTree(
        newIdentNode($i.AppId),
        appStmt
      )

    echo "ret=", ret.astGenRepr
    ret

  macro AppEmptyMacro(appId {.inject.}: AppId): untyped =
    quote do:
      echo `appId`

  macro AppAbortMacro(appId {.inject.}: AppId, abortBlock {.inject.}: typed): untyped =
    quote do:
      echo `appId`
      break `abortBlock`

  macro AppListenMacro(appId {.inject.}: AppId): untyped =
    quote do:
      echo `appId`

  macro AppRoutesMacro(appId {.inject.}: AppId): untyped =
    quote do:
      echo `appId`

  macro AppGetMacro(appId {.inject.}: AppId): untyped =
    quote do:
      echo `appId`

  macro AppPostMacro(appId {.inject.}: AppId): untyped =
    quote do:
      echo `appId`

  proc serverWorker(arg: ThreadArg) {.thread.} =
    echo "serverWorker ", arg.threadId
    var events: array[cfg.epollEventsSize, EpollEvent]
    template pevents: ptr UncheckedArray[EpollEvent] = cast[ptr UncheckedArray[EpollEvent]](addr events)
    var nfd: cint
    var nfdCond: bool
    var evIdx: int
    var client {.inject.}: Client

    template nextEv() =
      inc(evIdx); if evIdx >= nfd: break

    block WaitLoop:
      while true:
        nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events), cfg.epollEventsSize.cint, -1.cint)
        nfdCond = likely(nfd > 0)
        if nfdCond:
          evIdx = 0
          while true:
            client = cast[Client](pevents[evIdx].data)
            {.computedGoto.}
            appCaseBody(abortBlock = WaitLoop)

  let cpuCount = countProcessors()
  var serverWorkerNum = when cfg.serverWorkerNum < 0: cpuCount else: cfg.serverWorkerNum
  echo "server workers: ", serverWorkerNum, "/", cpuCount

  var threads = newSeq[Thread[WrapperThreadArg]](serverWorkerNum)
  for i in 0..<serverWorkerNum:
    createThreadWrapper(threads[i], serverWorker, ThreadArg(argType: ThreadArgType.ThreadId, threadId: i))
  joinThreads(threads)

  var retSockCtlClose = sockCtl.cint.close()
  if retSockCtlClose != 0:
    echo "error: close sockCtl"

  var retEpfdClose = epfd.close()
  if retEpfdClose != 0:
    echo "error: close epfd"

  clients.deallocShared()
