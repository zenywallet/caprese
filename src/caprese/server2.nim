# Copyright (c) 2024 zenywallet

import std/macros

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

macro newAppId(appType: static AppType): int =
  appIdTypeList.add(appType)
  inc(curAppId)
  echo "newAppId: appId=", curAppId, " appType=", appType
  echo "appIdTypeList=", appIdTypeList, " "
  newLit(curAppId)

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
      echo "server ", newAppId(AppListen)
      body

    macro routes(routesBody: untyped): untyped =
      var ret = newStmtList()
      ret.add quote do:
        echo "routes "
      ret[0].add(newLit(newAppId(AppRoutes)))
      ret.add(routesBody)
      ret

    macro get(url: string, getBody: untyped): untyped =
      quote do:
        echo "get ", newAppId(AppGet)

    macro post(url: string, postBody: untyped): untyped =
      quote do:
        echo "post ", newAppId(AppPost)

    macro serverBodyMacro(): untyped =
      serverBody
    serverBodyMacro()

  parseBody()

  genAppIdEnum()
  for a in AppId:
    echo a
