# Copyright (c) 2024 zenywallet

import std/macros

echo "welcome server2!"

type
  AppType2* = enum
    AppEmpty
    AppAbort
    AppListen
    AppRoutes
    AppRoutesRecv
    AppRoutesSend
    AppGet
    AppGetSend
    AppPost
    AppPostSend

var curAppId {.compileTime.} = 1
var appIdTypeList2* {.compileTime.} = @[AppType2.AppEmpty, AppType2.AppAbort]

proc newAppId*(appType: static AppType2): int {.discardable.} =
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
              newIdentNode("cuint")
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

  const cmdList = ["get", "stream", "public", "certificates", "acme",
          "post", "head", "put", "delete", "connect", "options", "trace", "patch"]

  macro genCmdListType(objName, varType: untyped): untyped =
    result = nnkTypeSection.newTree(
      nnkTypeDef.newTree(
        objName,
        newEmptyNode(),
        nnkObjectTy.newTree(
          newEmptyNode(),
          newEmptyNode(),
          nnkRecList.newTree()
        )
      )
    )
    for cmd in cmdList:
      result[0][2][2].add nnkIdentDefs.newTree(
        newIdentNode(cmd),
        varType,
        newEmptyNode()
      )

  genCmdListType(RoutesCmdFlag, bool)
  genCmdListType(RoutesCmdCount, int)

  var routesCmdFlagList {.compileTime.}: seq[RoutesCmdFlag]
  var routesCmdCountList {.compileTime.}: seq[RoutesCmdCount]

  proc newRoutesFlag() =
    routesCmdFlagList.add(RoutesCmdFlag())
    routesCmdCountList.add(RoutesCmdCount())
    echo "new routesCmdFlagList=", routesCmdFlagList

  macro getField(obj: object, field: static string): untyped =
    newDotExpr(obj, ident(field))

  macro staticIdentStr(s: untyped): untyped = newLit($s)

  template setRoutesMap(cmd: untyped, flag: bool = true) =
    routesCmdFlagList[^1].getField(staticIdentStr(cmd)) = flag
    inc(routesCmdCountList[^1].getField(staticIdentStr(cmd)))
    echo "routesCmdFlagList=", routesCmdFlagList
    echo "routesCmdCountList=", routesCmdCountList

  macro parseBody() =
    macro send(dummy: untyped): untyped = quote do: SendResult.None

    macro addServer(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var routesProc = genSym(nskProc, "routesProc")
      quote do:
        echo "server ", newAppId(AppType2.AppListen)
        proc `routesProc`(): SendResult = `body`
        discard `routesProc`()

    macro routes(routesBody: untyped): untyped =
      quote do:
        newRoutesFlag()
        echo "routes ", newAppId(AppType2.AppRoutes)
        echo "routes recv ", newAppId(AppType2.AppRoutesRecv)
        echo "routes send ", newAppId(AppType2.AppRoutesSend)
        defer:
          var cmdFlag = routesCmdFlagList[^1]
          var cmdCount = routesCmdCountList[^1]
          echo cmdFlag
          echo cmdCount
          if cmdFlag.get:
            for _ in 0..<cmdCount.get:
              newAppId(AppType2.AppGet)
            newAppId(AppType2.AppGetSend)
          if cmdFlag.post:
            for _ in 0..<cmdCount.post:
              newAppId(AppType2.AppPost)
            newAppId(AppType2.AppPostSend)
        `routesBody`

    macro get(url: string, getBody: untyped): untyped =
      quote do:
        setRoutesMap(get)
        echo "get"

    macro post(url: string, postBody: untyped): untyped =
      quote do:
        setRoutesMap(post)
        echo "post"

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
      sockUpperReserved: cint
      appId: AppId
      ev: EpollEvent
      ev2: EpollEvent
      recvBuf: ptr UncheckedArray[byte]
      recvPos: ptr UncheckedArray[byte]
      recvLen: int
      sendBuf: ptr UncheckedArray[byte]
      when cfg.sendBufExpand: sendBufSize: int
      sendPos: ptr UncheckedArray[byte]
      sendLen: int
      threadId: int
      whackaMole: bool
      prev: ptr ClientObj2
      next: ptr ClientObj2
      when cfg.clientLock: lock: Lock

    Client2 = ptr ClientObj2

  let cpuCount = countProcessors()
  var serverWorkerNum = when cfg.serverWorkerNum < 0: cpuCount else: cfg.serverWorkerNum
  var multiProcessThreadNum = when cfg.multiProcessThreadNum < 0: cpuCount else: cfg.multiProcessThreadNum
  var threadNum = when cfg.multiProcess: multiProcessThreadNum else: serverWorkerNum

  when cfg.multiProcess:
    var processWorkerId = 0
    if serverWorkerNum > 1:
      var forkCount = 1
      var pid = fork()
      while pid != 0:
        inc(forkCount)
        if forkCount >= serverWorkerNum:
          break
        pid = fork()
      if pid == 0:
        processWorkerId = forkCount * multiProcessThreadNum

  var clients2: ptr UncheckedArray[ClientObj2]
  var clientFreePool2 = queue2.newQueue[Client2]()

  proc initClient() =
    clients2 = cast[ptr UncheckedArray[ClientObj2]](allocShared0(sizeof(ClientObj2) * cfg.clientMax))

    for i in 0..<cfg.clientMax:
      var client = addr clients2[i]
      client.sock = osInvalidSocket
      client.sockUpperReserved = -1.cint
      client.appId = AppId0_AppEmpty
      client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
      client.ev.data = cast[EpollData](client)
      client.ev2.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
      client.ev2.data = cast[EpollData](client)
      client.recvBuf = nil
      client.recvPos = nil
      client.recvLen = 0
      client.sendBuf = nil
      when cfg.sendBufExpand: client.sendBufSize = 0
      client.sendPos = nil
      client.sendLen = 0
      client.threadId = -1
      client.whackaMole = false
      client.prev = nil
      client.next = nil
      when cfg.clientLock: initLock(client.lock)
      var retAddFreePool = clientFreePool2.add(client)
      if not retAddFreePool: raise

  proc freeClient() =
    when cfg.clientLock:
      for i in 0..<cfg.clientMax:
        var client = addr clients2[i]
        deinitLock(client.lock)
    clients2.deallocShared()

  var clientRingLock: Lock
  var clientRingRootObj: ClientObj2
  var clientRingRoot: Client2
  var clientRingCount: int

  proc initClientRing() =
    initLock(clientRingLock)
    clientRingRootObj.sock = osInvalidSocket
    clientRingRootObj.sockUpperReserved = -1.cint
    clientRingRootObj.appId = AppId0_AppEmpty
    clientRingRootObj.prev = addr clientRingRootObj
    clientRingRootObj.next = addr clientRingRootObj
    clientRingRoot = addr clientRingRootObj
    clientRingCount = 0

  proc freeClientRing() =
    deinitLock(clientRingLock)

  proc addClientRing(client: Client2) {.inline.} =
    acquire(clientRingLock)
    client.prev = clientRingRoot.prev
    client.next = clientRingRoot
    clientRingRoot.prev.next = client
    clientRingRoot.prev = client
    inc(clientRingCount)
    release(clientRingLock)

  proc delClientRing(client: Client2) {.inline.} =
    acquire(clientRingLock)
    client.prev.next = client.next
    client.next.prev = client.prev
    dec(clientRingCount)
    release(clientRingLock)

  proc atomic_compare_exchange_n(p: ptr int, expected: ptr int, desired: int, weak: bool,
                                success_memmodel: int, failure_memmodel: int): bool
                                {.importc: "__atomic_compare_exchange_n", nodecl, discardable.}

  proc close(client: Client2, lockFlag: static bool = true) {.inline.} =
    var sockInt = cast[ptr int](addr client.sock)[] # sock + sockUpperReserved(-1) = 8 bytes
    if client.sock != osInvalidSocket and
      atomic_compare_exchange_n(cast[ptr int](addr client.sock),
                                cast[ptr int](addr sockInt),
                                osInvalidSocket.int, false, 0, 0):
      var sockCint = cast[cint](sockInt) # cast lower only
      var retClose = sockCint.close()
      if retClose != 0: raise
      when cfg.clientLock and lockFlag: acquire(client.lock)
      if not client.recvBuf.isNil:
        client.recvBuf.deallocShared()
        client.recvBuf = nil
        client.recvPos = nil
        client.recvLen = 0
      if not client.sendBuf.isNil:
        client.sendBuf.deallocShared()
        client.sendBuf = nil
        when cfg.sendBufExpand: client.sendBufSize = 0
        client.sendPos = nil
        client.sendLen = 0
      when cfg.clientLock and lockFlag: release(client.lock)
      #client.whackaMole = false
      delClientRing(client)
      clientFreePool2.addSafe(client)

  proc eventfd(initval: cuint, flags: cint): cint {.importc.}

  var clientMonitorFd = eventfd(0, O_CLOEXEC or O_NONBLOCK)
  var fds: array[1, TPollfd]
  fds[0].events = posix.POLLIN
  fds[0].fd = clientMonitorFd

  var clientMonitorThread: Thread[void]

  proc clientMonitor() {.thread.} =
    var checkTimeout = cfg.connectionTimeout * 1000
    while true:
      var num = poll(addr fds[0], 1, checkTimeout)
      if num == 0:
        var clientRing = clientRingRoot.next
        while clientRing != clientRingRoot:
          if clientRing.whackaMole:
            clientRing.close()
          else:
            clientRing.whackaMole = true
          clientRing = clientRing.next
      else:
        break

  proc abortClientMonitor() =
    var value: uint64 = 1
    var retWrite = write(fds[0].fd, addr value, sizeof(value))
    if retWrite != sizeof(value):
      echo "error: abort client monitor"

  proc startClientMonitor() =
    createThread(clientMonitorThread, clientMonitor)

  proc stopClientMonitor() =
    abortClientMonitor()
    joinThread(clientMonitorThread)
    var retClose = clientMonitorFd.close()
    if retClose != 0:
      echo "error: close client monitor"

  when cfg.clientThreadAssign == DynamicAssign or (cfg.multiProcess and cfg.clientThreadAssign == AutoAssign):
    var epfd: cint = epoll_create1(O_CLOEXEC)
    if epfd < 0: raise
  else:
    var epfds = cast[ptr UncheckedArray[cint]](allocShared0(sizeof(cint) * threadNum))
    for i in 0..<threadNum:
      epfds[i] = epoll_create1(O_CLOEXEC)
      if epfds[i] < 0: raise

  var sockCtl = createNativeSocket()
  if sockCtl == osInvalidSocket: raise

  var rcvBufRes: cint
  var rcvBufSize = sizeof(rcvBufRes).SockLen
  var retGetSockOpt = sockCtl.getsockopt(SOL_SOCKET.cint, SO_RCVBUF.cint, addr rcvBufRes, addr rcvBufSize)
  if retGetSockOpt < 0: raise
  var workerRecvBufSize = rcvBufRes.int
  echo "workerRecvBufSize=", workerRecvBufSize
  var workerSendBufSize = workerRecvBufSize

  var abortClient: ClientObj2
  abortClient.sock = sockCtl
  abortClient.appId = AppId1_AppAbort
  abortClient.ev.events = EPOLLIN
  abortClient.ev.data = cast[EpollData](addr abortClient)

  proc abortServer() =
    when cfg.clientThreadAssign == DynamicAssign or (cfg.multiProcess and cfg.clientThreadAssign == AutoAssign):
      if epfd > 0:
        var e = epoll_ctl(epfd, EPOLL_CTL_ADD, sockCtl.cint, addr abortClient.ev)
        if e != 0:
          echo "error: abort epoll"
    else:
      for i in 0..<threadNum:
        if epfds[i] > 0:
          var e = epoll_ctl(epfds[i], EPOLL_CTL_ADD, sockCtl.cint, addr abortClient.ev)
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
    listenServer.recvBuf = nil
    listenServer.recvPos = nil
    listenServer.recvLen = 0
    listenServer.sendBuf = nil
    when cfg.sendBufExpand: listenServer.sendBufSize = 0
    listenServer.sendPos = nil
    listenServer.sendLen = 0
    listenServer.threadId = -1
    listenServer.whackaMole = false

  var curSrvId {.compileTime.} = 0
  var curRoutesId {.compileTime.} = 0
  var routesBodyList {.compileTime.}: seq[NimNode]
  var routesProcList {.compileTime.}: seq[NimNode]

  type
    SendProcType {.size: sizeof(cuint).} = enum
      SendProc1_Prev2
      SendProc1_Prev1
      SendProc2
      SendProc3_Prev2
      SendProc3_Prev1

  macro getRoutesBody(): untyped =
    var body = routesBodyList[curRoutesId]
    var routesProc = genSym(nskProc, "routesProc")
    quote do:
      proc `routesProc`(): SendResult = `body`
      `routesProc`()

  macro nextRoutesBody() =
    inc(curRoutesId)

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
      var body0 = body[0]

      routesBodyList.add quote do:
        `body0`

      routesProcList.add genSym(nskProc, "routesProc")

      quote do:
        echo "server: ", `bindAddress`, ":", `port`, " srvId=", `srvId`

        var aiList: ptr AddrInfo = nativesockets.getAddrInfo(`bindAddress`, `port`.Port, Domain.AF_UNSPEC)
        let domain = aiList.ai_family.toKnownDomain.get
        let sock = createNativeSocket(domain)
        if sock == osInvalidSocket: raise
        if sock.setsockopt(SOL_SOCKET.cint, SO_REUSEADDR.cint, addr optval, sizeof(optval).SockLen) < 0:
          raise
        when cfg.reusePort or cfg.multiProcess:
          if sock.setsockopt(SOL_SOCKET.cint, SO_REUSEPORT.cint, addr optval, sizeof(optval).SockLen) < 0:
            raise

        let retBind = sock.bindAddr(aiList.ai_addr, aiList.ai_addrlen.SockLen)
        if retBind < 0: raise
        freeaddrinfo(aiList)
        let retListen = sock.listen()
        if retListen < 0: raise
        sock.setBlocking(false)

        listenServers[`srvId`].sock = sock
        listenServers[`srvId`].appId = `appId`
        when cfg.multiProcess:
          when cfg.clientThreadAssign == FixedAssign:
            for i in 0..<threadNum:
              var retCtl = epoll_ctl(epfds[i], EPOLL_CTL_ADD, sock, addr listenServers[`srvId`].ev2)
              if retCtl != 0: raise
          else:
            var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, addr listenServers[`srvId`].ev2)
            if retCtl != 0: raise
        elif cfg.clientThreadAssign == DynamicAssign:
          var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, addr listenServers[`srvId`].ev)
          if retCtl != 0: raise
        else:
          for i in 0..<threadNum:
            var retCtl = epoll_ctl(epfds[i], EPOLL_CTL_ADD, sock, addr listenServers[`srvId`].ev2)
            if retCtl != 0: raise

    macro serverBodyMacro(): untyped =
      var extractServerBody = serverBody.copy()
      extractServerBody
    serverBodyMacro()

  extractBody()

  macro routes(routesBody: untyped): untyped = routesBody

  macro get(url: string, getBody: untyped): untyped =
    quote do:
      if `url`.len == reqHeaderUrlSize and equalMem(cast[pointer](reqHeaderUrlPos), `url`.cstring,  `url`.len):
        when returnExists(body): `getBody` else: return `getBody`

  macro post(url: string, postBody: untyped): untyped =
    quote do:
      if `url`.len == reqHeaderUrlSize and equalMem(cast[pointer](reqHeaderUrlPos), `url`.cstring,  `url`.len):
        when returnExists(body): `postBody` else: return `postBody`

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

  macro appRoutesBase(): untyped =
    result = quote do:
      echo "appRoutesBase"

      proc send(data: seq[byte] | string | Array[byte]): SendResult {.discardable.} =
        template sendProc1(nextAppOffset: cuint): SendResult =
          let sendlen = client.sock.send(addr data[0], data.len.cint,  MSG_NOSIGNAL)
          if sendlen == data.len: SendResult.Success
          elif sendlen == 0: SendResult.None
          elif sendlen > 0:
            var left = data.len - sendlen
            if client.sendBuf.isNil:
              if left <= sendBufSize:
                client.sendBuf = sendBuf
                client.sendBufSize = sendBufSize
                copyMem(sendBuf, addr data[sendlen], left)
                client.sendPos = sendBuf
                client.sendLen = left
                client.appId = (client.appId.cuint + nextAppOffset).AppId
                var e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_MOD, client.sock.cint, addr client.ev2)
                if e != 0:
                  echo "error: client epoll mod"
                sendBuf = cast[ptr UncheckedArray[byte]](allocShared(workerSendBufSize))
                sendBufSize = workerSendBufSize
                SendResult.Pending
              else:
                when cfg.sendBufExpand:
                  let leftReserve = left div 2 + left
                  client.sendBuf = cast[ptr UncheckedArray[byte]](allocShared(leftReserve))
                  client.sendBufSize = leftReserve
                  copyMem(client.sendBuf, addr data[sendlen], left)
                  client.sendPos = client.sendBuf
                  client.sendLen = left
                  client.appId = (client.appId.cuint + nextAppOffset).AppId
                  var e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_MOD, client.sock.cint, addr client.ev2)
                  if e != 0:
                    echo "error: client epoll mod"
                  SendResult.Pending
                else:
                  SendResult.Error
            else:
              when cfg.sendBufExpand:
                if left > client.sendBufSize:
                  let leftReserve = left div 2 + left
                  client.sendBuf = cast[ptr UncheckedArray[byte]](client.sendBuf.reallocShared(leftReserve))
                  client.sendBufSize = leftReserve
                copyMem(client.sendBuf, addr data[sendlen], left)
                client.sendPos = client.sendBuf
                client.sendLen = left
                client.appId = (client.appId.cuint + nextAppOffset).AppId
                var e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_MOD, client.sock.cint, addr client.ev2)
                if e != 0:
                  echo "error: client epoll mod"
                SendResult.Pending
              else:
                if left <= client.sendBufSize:
                  copyMem(client.sendBuf, addr data[sendlen], left)
                  client.sendPos = client.sendBuf
                  client.sendLen = left
                  client.appId = (client.appId.cuint + nextAppOffset).AppId
                  var e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_MOD, client.sock.cint, addr client.ev2)
                  if e != 0:
                    echo "error: client epoll mod"
                  SendResult.Pending
                else:
                  SendResult.Error
          elif errno == EAGAIN or errno == EWOULDBLOCK: SendResult.Pending
          elif errno == EINTR: send(data)
          else: SendResult.Error

        template sendProc2(): SendResult =
          var nextSize = curSendSize + data.len
          when cfg.sendBufExpand:
            if nextSize > sendBufSize:
              let nextReserveSize = nextSize div 2 + nextSize
              sendBuf = cast[ptr UncheckedArray[byte]](sendBuf.reallocShared(nextReserveSize))
              sendBufSize = nextReserveSize
            copyMem(addr sendBuf[curSendSize], addr data[0], data.len)
            curSendSize = nextSize
            SendResult.Pending
          else:
            if nextSize <= sendBufSize:
              copyMem(addr sendBuf[curSendSize], addr data[0], data.len)
              curSendSize = nextSize
              SendResult.Pending
            else:
              SendResult.Error

        template sendProc3Tmpl(nextAppOffset: cuint): SendResult {.dirty.} =
          let sendlen = client.sock.send(sendBuf, curSendSize.cint,  MSG_NOSIGNAL)
          if sendlen  == curSendSize: SendResult.Success
          elif sendlen == 0: SendResult.None
          elif sendlen > 0:
            var left = curSendSize - sendlen
            if not client.sendBuf.isNil:
              client.sendBuf.deallocShared()
            client.sendBuf = sendBuf
            client.sendBufSize = sendBufSize
            client.sendPos = cast[ptr UncheckedArray[byte]](addr sendBuf[sendlen])
            client.sendLen = left
            client.appId = (client.appId.cuint + nextAppOffset).AppId
            var e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_MOD, client.sock.cint, addr client.ev2)
            if e != 0:
              echo "error: client epoll mod"
            sendBuf = cast[ptr UncheckedArray[byte]](allocShared(workerSendBufSize))
            sendBufSize = workerSendBufSize
            SendResult.Pending
          elif errno == EAGAIN or errno == EWOULDBLOCK: SendResult.Pending
          elif errno == EINTR: send(data)
          else: SendResult.Error

        template sendProc3(nextAppOffset: cuint): SendResult =
          var nextSize = curSendSize + data.len
          when cfg.sendBufExpand:
            if nextSize > sendBufSize:
              let nextReserveSize = nextSize div 2 + nextSize
              sendBuf = cast[ptr UncheckedArray[byte]](sendBuf.reallocShared(nextReserveSize))
              sendBufSize = nextReserveSize
            copyMem(addr sendBuf[curSendSize], addr data[0], data.len)
            curSendSize = nextSize
            sendProc3Tmpl(nextAppOffset)
          else:
            if nextSize > sendBufSize:
              SendResult.Error
            else:
              copyMem(addr sendBuf[curSendSize], addr data[0], data.len)
              curSendSize = nextSize
              sendProc3Tmpl(nextAppOffset)

        {.computedGoto.}
        case curSendProcType
        of SendProc1_Prev2: sendProc1(2)
        of SendProc1_Prev1: sendProc1(1)
        of SendProc2: sendProc2()
        of SendProc3_Prev2: sendProc3(2)
        of SendProc3_Prev1: sendProc3(1)

      template parseHeaderUrl(pos, endPos: uint, RecvLoop: typed) =
        reqHeaderUrlPos = pos
        while true:
          if equalMem(cast[pointer](pos), " HTTP/1.".cstring, 8):
            reqHeaderUrlSize = pos - reqHeaderUrlPos
            inc(pos, 7)
            if equalMem(cast[pointer](pos), ".1\c\L".cstring, 4):
              reqHeaderMinorVer = 1
              inc(pos, 2)
              break
            elif equalMem(cast[pointer](pos), ".0\c\L".cstring, 4):
              reqHeaderMinorVer = 0
              inc(pos, 2)
              break
            else:
              inc(pos)
              reqHeaderMinorVer = int(cast[ptr char](cast[pointer](pos))[]) - int('0')
              inc(pos)
              if reqHeaderMinorVer < 0 or reqHeaderMinorVer > 9 or not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                client.close(false)
                break RecvLoop
              break
          inc(pos); if pos == endPos: break RecvLoop

    for i in 0..<routesBodyList.len:
      var routesBody = routesBodyList[i]
      var routesProc = routesProcList[i]

      result.add quote do:
        proc `routesProc`(sendProcType: SendProcType): SendResult =
          curSendProcType = sendProcType
          `routesBody`

  proc camel(s: string): string {.compileTime.} =
    result = s
    if result.len > 0 and result[0] >= 'A' and result[0] <= 'Z':
      result[0] = char(result[0].uint8 + 32'u8)

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
            newIdentNode(camel($appType) & "Macro"),
            newIdentNode($i.AppId),
            abortBlock
          )
        )
      else:
        nnkStmtList.newTree(
          nnkCall.newTree(
            newIdentNode(camel($appType) & "Macro"),
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

  macro appEmptyMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  macro appAbortMacro(appId: AppId, abortBlock: typed): untyped =
    quote do:
      echo `appId`
      break `abortBlock`

  macro appListenMacro(appId: AppId): untyped =
    quote do:
      while true:
        let clientSock = client.sock.accept4(cast[ptr SockAddr](addr sockAddress), addr addrLen, O_NONBLOCK)
        if cast[int](clientSock) > 0:
          if clientSock.setsockopt(Protocol.IPPROTO_TCP.cint, TCP_NODELAY.cint, addr optval, sizeof(optval).SockLen) < 0:
            raise
          while true:
            var newClient = clientFreePool2.pop()
            if not newClient.isNil:
              newClient.sock = clientSock
              newClient.appId = (client.appId.cuint + 1).AppId
              let e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_ADD, clientSock.cint, addr newClient.ev)
              if e != 0: raise
              newClient.whackaMole = false
              addClientRing(newClient)
              break
            elif clientFreePool2.count == 0:
              var retClose = clientSock.cint.close()
              if retClose != 0: raise
              break
          when cfg.multiProcess or cfg.clientThreadAssign != DynamicAssign:
            break
        else:
          break

  macro appRoutesMacro(appId: AppId): untyped =
    var routesProc = routesProcList[curRoutesId]

    quote do:
      when cfg.clientLock: acquire(client.lock)
      block RecvLoop:
        while true:
          retRecv = client.sock.recv(recvBuf, workerRecvBufSize, 0.cint)
          if retRecv >= 17:
            var endPos = cast[uint](recvBuf) + cast[uint](retRecv) - 4
            if equalMem(recvBuf, "GET ".cstring, 4):
              var pos = cast[uint](recvBuf) + 4
              parseHeaderUrl(pos, endPos, RecvLoop)

              curSendSize = 0
              while true:
                if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                  if pos == endPos:
                    var retRoutes = `routesProc`(SendProc1_Prev2)
                    if retRoutes <= SendResult.None:
                      client.close(false)
                    else:
                      client.whackaMole = false
                    break RecvLoop
                  else:
                    var retRoutes = `routesProc`(SendProc2)
                    if retRoutes <= SendResult.None:
                      client.close(false)
                      break RecvLoop
                    else:
                      inc(pos, 4)

                    if equalMem(cast[pointer](pos), "GET ".cstring, 4):
                      inc(pos, 4)
                      parseHeaderUrl(pos, endPos, RecvLoop)

                    while true:
                      if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                        if pos == endPos:
                          var retRoutes = `routesProc`(SendProc3_Prev2)
                          if retRoutes <= SendResult.None:
                            client.close(false)
                          else:
                            client.whackaMole = false
                          break RecvLoop
                        else:
                          var retRoutes = `routesProc`(SendProc2)
                          if retRoutes <= SendResult.None:
                            client.close(false)
                            break RecvLoop
                          else:
                            inc(pos, 4)

                        if equalMem(cast[pointer](pos), "GET ".cstring, 4):
                          inc(pos, 4)
                          parseHeaderUrl(pos, endPos, RecvLoop)

                      if pos >= endPos: break RecvLoop
                      inc(pos)
                else:
                  if pos >= endPos: break RecvLoop
                  inc(pos)

            elif equalMem(recvBuf, "POST".cstring, 4):
              var pos = cast[uint](recvBuf) + 5
              break RecvLoop

          elif retRecv == 0:
            client.close(false)
            break

          elif retRecv > 0:
            client.recvBuf = recvBuf
            #client.recvPos
            client.recvLen = retRecv
            recvBuf = cast[ptr UncheckedArray[byte]](allocShared0(workerRecvBufSize))
            client.appId = (client.appId.cuint + 1).AppId # AppRoutesRecv
            break
          else:
            if errno == EAGAIN or errno == EWOULDBLOCK:
              break
            elif errno == EINTR:
              continue
            else:
              client.close(false)
              break
      when cfg.clientLock: release(client.lock)

  macro appRoutesRecvMacro(appId: AppId): untyped =
    var routesBody = routesBodyList[curRoutesId]
    var routesProc = routesProcList[curRoutesId]

    quote do:
      echo `appId`

      proc `routesProc`(sendProcType: SendProcType): SendResult =
        curSendProcType = sendProcType
        `routesBody`

      var recvSize = workerRecvBufSize - client.recvLen
      if recvSize <= 0:
        client.close()
        break

      retRecv = client.sock.recv(addr client.recvBuf[client.recvLen], recvSize, 0.cint)
      if retRecv > 0:
        client.recvLen += retRecv

        block RecvLoop:
          while true:
            if client.recvLen >= 17:
              var endPos = cast[uint](client.recvBuf) + cast[uint](client.recvLen) - 4
              if equalMem(client.recvBuf, "GET ".cstring, 4):
                var pos = cast[uint](client.recvBuf) + 4
                parseHeaderUrl(pos, endPos, RecvLoop)

                curSendSize = 0
                while true:
                  if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                    if pos == endPos:
                      var retRoutes = `routesProc`(SendProc1_Prev1)
                      if retRoutes <= SendResult.None:
                        client.close()
                      else:
                        client.whackaMole = false
                        client.recvLen = 0
                      break RecvLoop
                    else:
                      var retRoutes = `routesProc`(SendProc2)
                      if retRoutes <= SendResult.None:
                        client.close()
                        break RecvLoop
                      else:
                        inc(pos, 4)

                      if equalMem(cast[pointer](pos), "GET ".cstring, 4):
                        inc(pos, 4)
                        parseHeaderUrl(pos, endPos, RecvLoop)

                      while true:
                        if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                          if pos == endPos:
                            var retRoutes = `routesProc`(SendProc3_Prev1)
                            if retRoutes <= SendResult.None:
                              client.close()
                            else:
                              client.whackaMole = false
                              client.recvLen = 0
                            break RecvLoop
                          else:
                            var retRoutes = `routesProc`(SendProc2)
                            if retRoutes <= SendResult.None:
                              client.close()
                              break RecvLoop
                            else:
                              inc(pos, 4)

                          if equalMem(cast[pointer](pos), "GET ".cstring, 4):
                            inc(pos, 4)
                            parseHeaderUrl(pos, endPos, RecvLoop)

                        if pos >= endPos: break RecvLoop
                        inc(pos)
                  else:
                    if pos >= endPos: break RecvLoop
                    inc(pos)

      elif retRecv == 0:
        client.close()
        break

      else:
        if errno == EAGAIN or errno == EWOULDBLOCK:
          break
        elif errno == EINTR:
          continue
        else:
          client.close()
          break

      echo "AppRoutesRecvMacro retRecv=", retRecv

  macro appRoutesSendMacro(appId: AppId): untyped =
    quote do:
      echo `appId`
      echo "data=", client.sendPos.toString(client.sendLen), client.sendLen
      when cfg.clientLock: acquire(client.lock)
      let sendlen = client.sock.send(client.sendPos, client.sendLen.cint,  MSG_NOSIGNAL)

      client.appId = (client.appId.cuint - 2).AppId
      var e = epoll_ctl(when declared(epfd2): epfd2 else: epfd, EPOLL_CTL_MOD, client.sock.cint, addr client.ev)
      if e != 0:
        echo "error: client epoll mod"
      when cfg.clientLock: release(client.lock)

  macro appGetMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  macro appGetSendMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  macro appPostMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  macro appPostSendMacro(appId: AppId): untyped =
    quote do:
      echo `appId`

  proc serverWorker(arg: ThreadArg) {.thread.} =
    echo "serverWorker ", arg.threadId
    var events: array[cfg.epollEventsSize, EpollEvent]
    template pevents: ptr UncheckedArray[EpollEvent] = cast[ptr UncheckedArray[EpollEvent]](addr events)
    var nfd: cint
    var nfdCond: bool
    var evIdx: int = 0
    var client: Client2
    var sockAddress: Sockaddr_in
    var addrLen: SockLen = sizeof(sockAddress).SockLen
    var retRecv: int
    var recvBuf = cast[ptr UncheckedArray[byte]](allocShared0(workerRecvBufSize))
    var recvBufSize = workerRecvBufSize
    var sendBuf = cast[ptr UncheckedArray[byte]](allocShared0(workerSendBufSize))
    var sendBufSize = workerSendBufSize
    var curSendSize: int
    var reqHeaderUrlPos: uint
    var reqHeaderUrlSize: uint
    var reqHeaderMinorVer: int
    var curSendProcType: SendProcType
    when cfg.clientThreadAssign == DynamicAssign or (cfg.multiProcess and cfg.clientThreadAssign == AutoAssign):
      discard
    else:
      var epfd = epfds[arg.threadId]
      var epfd2 = epfd

    appRoutesBase()

    template nextEv() =
      inc(evIdx); if evIdx >= nfd: break

    block WaitLoop:
      while true:
        nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events), cfg.epollEventsSize.cint, -1.cint)
        nfdCond = likely(nfd > 0)
        if nfdCond:
          while true:
            client = cast[Client2](pevents[evIdx].data)
            {.computedGoto.}
            appCaseBody(abortBlock = WaitLoop)
          evIdx = 0

  initClient()
  initClientRing()
  import std/strutils
  activeHeaderInit()
  when cfg.headerDate:
    startTimeStampUpdater(cfg)
  startClientMonitor()

  when cfg.multiProcess:
    if processWorkerId == 0:
      echo "server process workers: ", serverWorkerNum, "/", cpuCount
    var threads = newSeq[Thread[WrapperThreadArg]](multiProcessThreadNum)
    for i in 0..<multiProcessThreadNum:
      createThreadWrapper(threads[i], serverWorker, ThreadArg(argType: ThreadArgType.ThreadId, threadId: processWorkerId + i))
    joinThreads(threads)
  else:
    echo "server thread workers: ", serverWorkerNum, "/", cpuCount
    var threads = newSeq[Thread[WrapperThreadArg]](serverWorkerNum)
    for i in 0..<serverWorkerNum:
      createThreadWrapper(threads[i], serverWorker, ThreadArg(argType: ThreadArgType.ThreadId, threadId: i))
    joinThreads(threads)

  stopClientMonitor()
  when cfg.headerDate:
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

  when cfg.clientThreadAssign == DynamicAssign or (cfg.multiProcess and cfg.clientThreadAssign == AutoAssign):
    var retEpfdClose = epfd.close()
    if retEpfdClose != 0:
      echo "error: close epfd"
  else:
    for i in countdown(threadNum - 1, 0):
      var retEpfdClose = epfds[i].close()
      if retEpfdClose != 0:
        echo "error: close epfd"
    epfds.deallocShared()

  freeClientRing()
  freeClient()
