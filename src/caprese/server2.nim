# Copyright (c) 2024 zenywallet

import std/macros

echo "welcome server2!"

type
  AppType2* = enum
    AppEmpty
    AppAbort
    AppListen
    AppRoutes
    AppGet
    AppPost

var curAppId {.compileTime.} = 1
var appIdTypeList2* {.compileTime.} = @[AppType2.AppEmpty, AppType2.AppAbort]

proc newAppId*(appType: static AppType2): int =
  appIdTypeList2.add(appType)
  inc(curAppId)
  echo "newAppId: appId=", curAppId, " appType=", appType
  echo "appIdTypeList2=", appIdTypeList2, " "
  curAppId

macro genAppIdEnum*(): untyped =
  var appIdEnum = nnkTypeSection.newTree(
    nnkTypeDef.newTree(
      nnkPragmaExpr.newTree(
        newIdentNode("AppId"),
        nnkPragma.newTree(
          nnkExprColonExpr.newTree(
            newIdentNode("size"),
            nnkCall.newTree(
              newIdentNode("sizeof"),
              newIdentNode("cint")
            )
          )
        )
      ),
      newEmptyNode(),
      nnkEnumTy.newTree(
        newEmptyNode()
      )
    )
  )
  for i, appType in appIdTypeList2:
    appIdEnum[0][2].add(ident("AppId" & $i & "_" & $appType))
  appIdEnum

template parseServers*(serverBody: untyped) {.dirty.} =
  import std/options
  import std/cpuinfo

  macro parseBody() =
    macro addServer(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var routesProc = genSym(nskProc, "routesProc")
      quote do:
        echo "server ", newAppId(AppType2.AppListen)
        proc `routesProc`(): SendResult = `body`
        discard `routesProc`()

    macro routes(routesBody: untyped): untyped =
      quote do:
        echo "routes ", newAppId(AppType2.AppRoutes)
        `routesBody`

    macro get(url: string, getBody: untyped): untyped =
      quote do:
        echo "get ", newAppId(AppType2.AppGet)

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
    ClientObj2 = object
      sock: SocketHandle
      appId: AppId
      ev: EpollEvent
      ev2: EpollEvent
      sendBuf: ptr UncheckedArray[byte]
      sendPos: ptr UncheckedArray[byte]
      sendLen: int
      threadId: int
      whackaMole: bool

    Client2 = ptr ClientObj2

  var clients2 = cast[ptr UncheckedArray[ClientObj2]](allocShared0(sizeof(ClientObj2) * cfg.clientMax))
  var clientFreePool2 = queue2.newQueue[Client2]()

  for i in 0..<cfg.clientMax:
    var client = addr clients2[i]
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
    var retAddFreePool = clientFreePool2.add(client)
    if not retAddFreePool: raise

  proc close(client: Client2) {.inline.} =
    var retClose = client.sock.cint.close()
    if retClose != 0: raise
    if not client.sendBuf.isNil:
      client.sendBuf.deallocShared()
      client.sendBuf = nil
      client.sendPos = nil
      client.sendLen = 0
    client.whackaMole = false
    client.sock = osInvalidSocket
    clientFreePool2.addSafe(client)

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

  var abortClient: ClientObj2
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

  macro listenCountMacro(): untyped =
    var listenCount = 0
    for appType in appIdTypeList2:
      if appType == AppType2.AppListen:
        inc(listenCount)
    newLit(listenCount)
  const listenCount = listenCountMacro()

  var listenServers = cast[ptr UncheckedArray[ClientObj2]](allocShared0(sizeof(ClientObj2) * listenCount))
  for i in 0..<listenCount:
    var listenServer = addr listenServers[i]
    listenServer.sock = osInvalidSocket
    listenServer.appId = AppId0_AppEmpty
    listenServer.ev.events = EPOLLIN or EPOLLET
    listenServer.ev.data = cast[EpollData](listenServer)
    listenServer.ev2.events = EPOLLIN or EPOLLEXCLUSIVE
    listenServer.ev2.data = cast[EpollData](listenServer)
    listenServer.sendBuf = nil
    listenServer.sendPos = nil
    listenServer.sendLen = 0
    listenServer.threadId = -1
    listenServer.whackaMole = false

  var curSrvId {.compileTime.} = 0
  var curRoutesId {.compileTime.} = 0
  var routesBodyList {.compileTime.}: seq[NimNode]

  macro getRoutesBody(): untyped =
    var ret = routesBodyList[curRoutesId]
    inc(curRoutesId)
    ret

  var listenAppIdList {.compileTime.}: seq[AppId]
  macro listenAppIdMacro() =
    for i, appType in appIdTypeList2:
      if appType == AppType2.AppListen:
        listenAppIdList.add(i.AppId)
    echo "listenAppIdList=", listenAppIdList
  listenAppIdMacro()

  proc send(data: seq[byte] | string | Array[byte]): SendResult {.discardable.} =
    echo "send data.len=", data.len
    SendResult.Success

  proc extractBody() =
    macro addServer(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var srvId = curSrvId; inc(curSrvId)
      var appId = ident($listenAppIdList[srvId])
      var routesProc = genSym(nskProc, "routesProc")

      routesBodyList.add quote do:
        echo "routes"
        proc `routesProc`(): SendResult = `body`
        `routesProc`()

      quote do:
        echo "server: ", `bindAddress`, ":", `port`, " srvId=", `srvId`

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

        listenServers[`srvId`].sock = sock
        listenServers[`srvId`].appId = `appId`
        var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, addr listenServers[`srvId`].ev)
        if retCtl != 0: raise

    macro serverBodyMacro(): untyped =
      var extractServerBody = serverBody.copy()
      extractServerBody
    serverBodyMacro()

  extractBody()

  macro routes(routesBody: untyped): untyped = routesBody

  macro get(url: string, getBody: untyped): untyped =
    quote do:
      if `url`.len > 0:
        echo "get"
        `getBody`

  macro post(url: string, postBody: untyped): untyped =
    quote do:
      if `url`.len > 0:
        echo "post"
        `postBody`

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

  macro appCaseBody(abortBlock: typed): untyped =
    var ret = nnkCaseStmt.newTree(
      nnkDotExpr.newTree(
        newIdentNode("client"),
        newIdentNode("appId")
      )
    )
    for i, appType in appIdTypeList2:
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

  macro AppEmptyMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  macro AppAbortMacro(appId: AppId, abortBlock: typed): untyped =
    quote do:
      echo `appId`
      break `abortBlock`

  macro AppListenMacro(appId: AppId): untyped =
    quote do:
      echo `appId`
      while true:
        let clientSock = client.sock.accept4(cast[ptr SockAddr](addr sockAddress), addr addrLen, O_NONBLOCK)
        if cast[int](clientSock) > 0:
          if clientSock.setsockopt(Protocol.IPPROTO_TCP.cint, TCP_NODELAY.cint, addr optval, sizeof(optval).SockLen) < 0:
            raise
          while true:
            var newClient = clientFreePool2.pop()
            if not newClient.isNil:
              newClient.sock = clientSock
              newClient.appId = (client.appId.cint + 1).AppId
              let e = epoll_ctl(epfd, EPOLL_CTL_ADD, clientSock.cint, addr newClient.ev)
              if e != 0: raise
              break
            if clientFreePool2.count == 0:
              var retClose = clientSock.cint.close()
              if retClose != 0: raise
              break
        else:
          break

  macro AppRoutesMacro(appId: AppId): untyped =
    quote do:
      echo `appId`
      var ret = getRoutesBody()
      echo "getRoutesBody ret=", ret

  macro AppGetMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  macro AppPostMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  import std/strutils
  activeHeaderInit()
  startTimeStampUpdater(cfg)

  proc serverWorker(arg: ThreadArg) {.thread.} =
    echo "serverWorker ", arg.threadId
    var events: array[cfg.epollEventsSize, EpollEvent]
    template pevents: ptr UncheckedArray[EpollEvent] = cast[ptr UncheckedArray[EpollEvent]](addr events)
    var nfd: cint
    var nfdCond: bool
    var evIdx: int
    var client: Client2
    var sockAddress: Sockaddr_in
    var addrLen: SockLen = sizeof(sockAddress).SockLen

    template nextEv() =
      inc(evIdx); if evIdx >= nfd: break

    block WaitLoop:
      while true:
        nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events), cfg.epollEventsSize.cint, -1.cint)
        nfdCond = likely(nfd > 0)
        if nfdCond:
          evIdx = 0
          while true:
            client = cast[Client2](pevents[evIdx].data)
            {.computedGoto.}
            appCaseBody(abortBlock = WaitLoop)

  let cpuCount = countProcessors()
  var serverWorkerNum = when cfg.serverWorkerNum < 0: cpuCount else: cfg.serverWorkerNum
  echo "server workers: ", serverWorkerNum, "/", cpuCount

  var threads = newSeq[Thread[WrapperThreadArg]](serverWorkerNum)
  for i in 0..<serverWorkerNum:
    createThreadWrapper(threads[i], serverWorker, ThreadArg(argType: ThreadArgType.ThreadId, threadId: i))
  joinThreads(threads)

  stopTimeStampUpdater()

  for i in 0..<listenCount:
    var listenServer = addr listenServers[i]
    var retlistenServerClose = listenServer.sock.cint.close()
    if retlistenServerClose != 0:
      echo "error: listen server close #", i
  listenServers.deallocShared()

  var retSockCtlClose = sockCtl.cint.close()
  if retSockCtlClose != 0:
    echo "error: close sockCtl"

  var retEpfdClose = epfd.close()
  if retEpfdClose != 0:
    echo "error: close epfd"

  clients2.deallocShared()
