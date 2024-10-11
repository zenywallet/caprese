# Copyright (c) 2024 zenywallet

import std/macros

echo "welcome server2!"

template parseServers*(serverBody: untyped) =
  macro parseBody() =
    macro addServer(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped): untyped =
      echo "server"
      body

    macro routes(routesBody: untyped): untyped =
      var ret = newStmtList()
      ret.add quote do:
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
      serverBody
    serverBodyMacro()

  parseBody()
