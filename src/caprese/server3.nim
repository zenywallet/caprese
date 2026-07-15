# Copyright (c) 2025 zenywallet

import std/macros
import srvcmd
import utils

echo "welcome server3!"

var serverBodies {.compileTIme.}: seq[NimNode]
var srvId {.compileTime.} = 0
let lastServerId {.importc: "LASTSRV", nodecl.}: cint
var manualServerStart {.compileTime.} = false

macro internalServerStart(): untyped =
  result = newStmtList()
  for i, body in serverBodies:
    result.add quote do:
      doMacro:
        srvId = `i` + 1
      `body`

macro server*(ip, port, body: untyped): untyped {.srvcmd.} =
  echo "server ip=", ip.strVal, " port=", port.intVal
  inc(srvId)
  var capSrvBlock = ident("capSrvBlock" & $srvId)
  serverBodies.add quote do:
    block `capSrvBlock`:
      `body`

  newSrvCmdUsage()
  quote do:
    doMacro:
      withSrvCmd:
        setSrvCmdUsageMacro(server)
        proc parseDummy(): int {.compileTime, used.} =
          block `capSrvBlock`:
            `body`
    when not manualServerStart:
      {.passC: "-DLASTSRV=" & $`srvId`.}
      # Unnecessary code is removed through C language optimization
      if lastServerId == `srvId`:
        internalServerStart()

macro routes*(host, body: untyped): untyped {.srvcmd.} =
  var capSrvBlock = newIdentNode("capSrvBlock" & $srvId)
  quote do:
    if host == `host`:
      `body`
      break `capSrvBlock`

macro routes*(body: untyped): untyped {.srvcmd.} =
  var capSrvBlock = newIdentNode("capSrvBlock" & $srvId)
  quote do:
    `body`
    break `capSrvBlock`

macro addHeader*(body: untyped): untyped {.srvcmd.} =
  quote do:
    `body`

macro send*(body: untyped): untyped {.srvcmd.} =
  quote do:
    echo "send"

template reqHeader*(paramId: untyped): string {.srvcmd.} =
  when paramId == 2:
    setSrvCmdUsageMacro("reqHeaderHost")
  "reqHeader"

addSrvCmd("reqHeaderHost")

commitSrvCmd()

macro serverStart*(): untyped =
  manualServerStart = true
  quote do:
    {.passC: "-DLASTSRV=0".}
    internalServerStart()


when isMainModule:
  var host: string = "host2"

  template routes_tmpl =
    routes(host = "host3"):
      echo "server1 host3"
      echo reqHeader(2)
      "hello3".addHeader.send

  server(ip = "0.0.0.0", port = 8009):
    routes(host = "host1"):
      echo "server1 host1"
      "hello1".addHeader.send

    routes(host = "host2"):
      echo "server1 host2"
      "hello2".addHeader.send

    routes_tmpl()

  server(ip = "0.0.0.0", port = 8010):
    routes(host = "host2"):
      echo "server2 host2"
      "hello4".addHeader.send

  #serverStart()


  doMacro:
    for i in 0..getSrvCmdCount(0).server:
      echo getSrvCmdUsage(i)
