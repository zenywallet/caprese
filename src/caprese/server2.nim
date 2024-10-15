# Copyright (c) 2024 zenywallet

import std/macros
import std/epoll
import std/nativesockets
import std/posix
import std/options

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

  proc extractBody() =
    macro addServer(bindAddress {.inject.}: string, port {.inject.}: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var appId {.inject.} = ident("AppId2_AppListen")

      var ret = newStmtList quote do:
        echo "server: ", `bindAddress`, ":", `port`

        var aiList: ptr AddrInfo = nativesockets.getAddrInfo(`bindAddress`, `port`.Port, Domain.AF_UNSPEC)
        let domain = aiList.ai_family.toKnownDomain.get
        let sock = createNativeSocket(domain)
        if sock == osInvalidSocket: raise
        var optval = 1.cint
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

  var retSockCtlClose = sockCtl.cint.close()
  if retSockCtlClose != 0:
    echo "error: close sockCtl"

  var retEpfdClose = epfd.close()
  if retEpfdClose != 0:
    echo "error: close epfd"
