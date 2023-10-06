# Copyright (c) 2022 zenywallet

when not compileOption("threads"):
  {.error: "requires --threads:on option.".}

when isMainModule:
  {.define: DYNAMIC_FILES.}

import nativesockets
import server as serverlib
import contents
import files
import statuscode
import queue
import macros
import rlimit
import config
export nativesockets
export serverlib
export contents
export files
export statuscode
export queue
export config

var active* = true
var workerNum = 0

var onSigTermQuitBody {.compileTime.} = newStmtList()
macro onSigTermQuit(body: untyped) = discard onSigTermQuitBody.add(body)

template onQuit*(body: untyped) = onSigTermQuit(body)

macro addCfgDotExpr*(body: untyped): untyped =
  result = nnkStmtList.newTree()
  for i in 0..<body.len:
    if body[i].kind == nnkAsgn:
      var a = body[i]
      a[0] = nnkDotExpr.newTree(
        newIdentNode("cfg"),
        a[0]
      )
      result.add(a)

macro configCalls*(body: untyped): untyped =
  result = nnkStmtList.newTree()
  var flag = false
  for i in 0..<body.len:
    if body[i].kind == nnkCall:
      if $body[i][0] == "httpHeader":
        body[i][0] = newIdentNode("HttpTargetHeader")
        flag = true
      result.add(body[i])
  if flag:
    var alib = nnkFromStmt.newTree(
      newIdentNode("arraylib"),
      nnkAccQuoted.newTree(
        newIdentNode("@^")
      )
    )
    result.insert(0, alib)

template config*(body: untyped) {.dirty.} =
  var cfg* {.compileTime.}: Config = defaultConfig()
  macro addCfg() =
    addCfgDotExpr(body)
  addCfg()
  configCalls(body)

template cfgDefault() {.dirty.} =
  when not declared(cfg):
    var cfg* {.compileTime.}: Config = defaultConfig()

var initFlag {.compileTime.}: bool
macro init(): untyped =
  if initFlag: return
  initFlag = true
  quote do:
    cfgDefault()
    when cfg.debugLog: {.define: DEBUG_LOG.}

    serverInit()
    serverTagLib(cfg)

    when cfg.limitOpenFiles < 0:
      setMaxRlimitOpenFiles()
    else:
      const limitOpenFiles = cfg.limitOpenFiles
      setRlimitOpenFiles(limitOpenFiles)
    when cfg.sigPipeIgnore: signal(SIGPIPE, SIG_IGN)
    serverlib.abort = proc() {.thread.} =
      serverlib.serverStop()
      active = false
    when cfg.sigTermQuit:
      onSignal(SIGINT, SIGTERM):
        echo "bye from signal ", sig
        serverlib.abort()
        `onSigTermQuitBody`

macro server*(ssl: bool, ip: string, port: uint16, body: untyped): untyped =
  quote do:
    init()
    echo "server: ", `ip`, ":", `port`, (if `ssl`: " SSL" else: "")
    addServer(`ip`, `port`, false, `ssl`, `body`)

macro server*(ip: string, port: uint16, body: untyped): untyped =
  quote do:
    init()
    echo "server: ", `ip`, ":", `port`
    addServer(`ip`, `port`, false, false, `body`)

macro server*(unix: string, body: untyped): untyped =
  quote do:
    init()
    echo "server: unix:", `unix`
    addServer(`unix`, 0, true, false, `body`)

template serverHttp*(ip: string, port: uint16, body: untyped) =
  server(false, ip, port, body)

template serverHttps*(ip: string, port: uint16, body: untyped) =
  server(true, ip, port, body)

macro worker*(num: int, body: untyped): untyped =
  var workerRootBlockBody = nnkStmtList.newTree(
    nnkBlockStmt.newTree(
      newIdentNode("workerRoot"),
      body
    )
  )
  quote do:
    init()
    atomicInc(workerNum, `num`)
    var workerThreads: array[`num`, Thread[void]]
    block:
      proc workerProc() {.thread.} = `workerRootBlockBody`
      for i in 0..<`num`:
        createThread(workerThreads[i], workerProc)

template worker*(body: untyped) = worker(1, body)

proc newPending*[T](limit: int): Queue[tuple[cid: ClientId, data: T]] {.inline.} =
  newQueue[tuple[cid: ClientId, data: T]](limit)

macro pendingBody*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], data: T): untyped =
  quote do:
    proc pendingProc(): SendResult {.discardable.} =
      when not declared(client):
        {.error: "ClientId of pending can be ommitted only in server blocks.".}
      let cid = client.markPending()
      if `reqs`.send((cid, `data`)):
        return SendResult.Pending
      else:
        return SendResult.Error

template pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], data: T): SendResult {.dirty.} =
  block:
    when not declared(reqClient):
      {.error: "ClientId of pending can be ommitted only in server blocks.".}
    var client = reqClient()
    pendingBody(reqs, data)
    pendingProc()

proc pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], req: tuple[cid: ClientId, data: T]): SendResult {.inline, discardable.} =
  if reqs.send(req):
    SendResult.Pending
  else:
    SendResult.Error

proc pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], cid: ClientId, data: T): SendResult {.inline, discardable.} =
  if reqs.send((cid, data)):
    SendResult.Pending
  else:
    SendResult.Error

template exitWorker*() = break workerRoot

template getPending*(reqs: auto): auto =
  let ret = reqs.recv()
  if not active: exitWorker()
  ret


when isMainModule:
  when defined(EXAMPLE1):
    server(ssl = true, ip = "0.0.0.0", port = 8009):
      routes:
        get "/":
          return send("Hello!".addHeader())

        return send("Not found".addHeader(Status404))

    serverStart()

  elif defined(BENCHMARK1):
    config:
      sslLib = None

    server(ip = "0.0.0.0", port = 8089):
      routes:
        get "/": return "Hello, World!".addHeader("text").send
        return "Not found".addHeader(Status404, "text").send

    serverStart()

  else:
    import std/os

    if paramCount() != 1:
      echo "usage: caprese <public folder>"
      quit(QuitFailure)

    var publicPath = paramStr(1)
    initDynamicFile(publicPath)

    server(ssl = true, ip = "127.0.0.1", port = 8009):
      routes(host = "localhost"):
        var fileContentResult = getDynamicFile(reqUrl())
        if fileContentResult.err == FileContentSuccess:
          var fileContent = fileContentResult.data
          return send(fileContent.content.addHeader(EncodingType.None, fileContent.md5, Status200, fileContent.mime))
        return send("Not found".addHeader(Status404))

    serverStart()


  #[
  import std/strformat
  import std/re

  type
    PendingData = object
      url: string

  config:
    sslLib = BearSSL
    debugLog = true

    httpHeader:
      HeaderHost: "Host"
      HeaderAcceptEncoding: "Accept-Encoding"
      HeaderConnection: "Connection"

  var reqs = newPending[PendingData](limit = 100)

  onQuit:
    reqs.drop()

  const IndexHtml = staticHtmlDocument:
    buildHtml(html):
      head:
        meta(charset="utf-8")
      body:
        text "welcome"

  const TestHtml = staticHtmlDocument:
    buildHtml(html):
      head:
        meta(charset="utf-8")
      body:
        text "[worker] {urlText}"

  const WsTestJs = staticScript:
    import jsffi
    import jslib

    var testDataBase = ""
    var testData = ""
    for i in 0..<100:
      testDataBase = testDataBase & "[testdata]"
    for i in 0..<100:
      testData = testData & testDataBase

    proc wsUrl(domain, path: cstring): cstring =
      var prot = if window.location.protocol == "https:".toJs: "wss:".cstring else: "ws:".cstring
      var port = window.location.port
      var sport = if port == 80.toJs or port == 443.toJs: "".cstring else: ":".cstring & port.to(cstring)
      result = prot & "//".cstring & domain & sport & "/".cstring & path

    var ws = newWebSocket(wsUrl("localhost", "ws"), "caprese-0.1")
    proc testSend() =
      if ws.readyState == WebSocket.OPEN:
        ws.send(testData)
    setInterval(testSend, 3000)

  const WsTestMinJs = scriptMinifier(code = WsTestJs, extern = "")

  const WsTestHtml = staticHtmlDocument:
    buildHtml(html):
      head:
        meta(charset="utf-8")
      body:
        text "websocket test"
        script: verbatim WsTestMinJs

  worker(num = 2):
    while true:
      let req = reqs.getPending()
      let urlText = sanitizeHtml(req.data.url)
      let clientId = req.cid
      clientId.send(fmt(TestHtml).addHeader())

  server(ssl = true, ip = "0.0.0.0", port = 8009):
    routes(host = "localhost"):
      certificates(path = "./certs/site_a"):
        privKey: "privkey.pem"
        fullChain: "fullchain.pem"

      # client: Client
      # url: string
      # headers: Headers

      get "/":
        return send(IndexHtml.addHeader())

      get "/home", "/main", "/about":
        return send(IndexHtml.addHeader())

      get re"/([a-z]+)(\d+)":
        return send(sanitizeHtml(matches[0] & "|" & matches[1]).addHeader())

      get "/test":
        return reqs.pending(PendingData(url: reqUrl))

      get "/wstest":
        return send(WsTestHtml.addHeader())

      stream(path = "/ws", protocol = "caprese-0.1"):
        # client: Client
        onOpen:
          echo "onOpen"

        # client: Client
        # opcode: WebSocketOpCode
        # data: ptr UncheckedArray[byte]
        # size: int
        onMessage:
          echo "onMessage"
          return wsSend(data.toString(size), WebSocketOpcode.Binary)

        onClose:
          echo "onClose"

      stream(path = "/ws2", protocol = "caprese-0.1"):
        # client: Client
        onOpen:
          echo "onOpen"

        # client: Client
        # opcode: WebSocketOpCode
        # data: ptr UncheckedArray[byte]
        # size: int
        echo "stream test"
        case opcode
        of WebSocketOpcode.Binary, WebSocketOpcode.Text, WebSocketOpcode.Continue:
          echo "onMessage"
          return wsSend(data.toString(size), WebSocketOpcode.Binary)
        of WebSocketOpcode.Ping:
          return wsSend(data.toString(size), WebSocketOpcode.Pong)
        of WebSocketOpcode.Pong:
          debug "pong ", data.toString(size)
          return SendResult.Success
        else: # WebSocketOpcode.Close
          echo "onClose"
          return SendResult.None

      let urlText = sanitizeHtml(reqUrl)
      return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))

  server(ip = "0.0.0.0", port = 8089):
    routes(host = "localhost"):
      get "/":
        return send(IndexHtml.addHeader())

      let urlText = sanitizeHtml(reqUrl)
      return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))

  serverStart()
  ]#
