# Copyright (c) 2024 zenywallet

import std/macros
import std/epoll

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

  proc extractBody() =
    macro addServer(bindAddress {.inject.}: string, port {.inject.}: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      var ret = newStmtList quote do:
        echo "server: ", `bindAddress`, ":", `port`
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
