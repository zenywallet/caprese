# Copyright (c) 2022 zenywallet

when not compileOption("threads"):
  {.error: "requires --threads:on option.".}

import nativesockets
import posix
import serverdef
import contents
import statuscode
import queue
import macros
export nativesockets
export posix
export serverdef
export contents
export statuscode
export queue

var active* = true
var workerNum = 0

var onSigTermQuitBody {.compileTime.} = newStmtList()
macro onSigTermQuit*(body: untyped) = discard onSigTermQuitBody.add(body)

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

var initFlag {.compileTime.}: bool
macro init(): untyped =
  if initFlag: return
  initFlag = true
  quote do:
    when cfg.debugLog: {.define: DEBUG_LOG.}
    when cfg.ssl:
      {.define: ENABLE_SSL.}
      when cfg.sslLib == BearSSL:
        {.define: USE_BEARSSL.}
      elif cfg.sslLib == OpenSSL:
        {.define: USE_OPENSSL.}
      elif cfg.sslLib == LibreSSL:
        {.define: USE_LIBRESSL.}
      elif cfg.sslLib == BoringSSL:
        {.define: USE_BORINGSSL.}

    import server as serverlib
    export serverlib

    when cfg.maxOpenFiles:
      setMaxRlimitOpenFiles()
    else:
      setRlimitOpenFiles(cfg.limitOpenFiles)
    when cfg.sigPipeIgnore: signal(SIGPIPE, SIG_IGN)
    serverlib.abort = proc() {.thread.} =
      serverlib.serverStop()
      active = false
    when cfg.sigTermQuit:
      onSignal(SIGINT, SIGTERM):
        echo "bye from signal ", sig
        serverlib.abort()
        `onSigTermQuitBody`

#[
macro get*(url: string, body: untyped): untyped =
  quote do:
    if url == `url`:
      `body`
]#

template setStream(body: untyped) {.dirty.} =
  proc streamMain(client: Client, opcode: WebSocketOpCode,
                  data: ptr UncheckedArray[byte], size: int): SendResult =
    body
  setStreamMain(streamMain)

macro stream0*(body: untyped): untyped =
  quote do:
    setStream(`body`)

macro server*(bindAddress: string, port: uint16, body: untyped): untyped =
  quote do:
    init()
    echo "bind address: ", `bindAddress`
    echo "port: ", `port`
    addServer(`bindAddress`, `port`, `body`)

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
  import strformat
  import std/re

  type
    PendingData = object
      url: string

  config:
    ssl = false
    sslLib = OpenSSL
    debugLog = true

    httpHeader:
      HeaderHost: "Host"
      HeaderAcceptEncoding: "Accept-Encoding"
      HeaderConnection: "Connection"

  var reqs = newPending[PendingData](limit = 100)

  onSigTermQuit:
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
    var ws = newWebSocket("ws://localhost:8009/ws", "caprese-0.1")
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
        script verbatim WsTestMinJs

  worker(num = 2):
    while true:
      let req = reqs.getPending()
      let urlText = sanitizeHtml(req.data.url)
      let clientId = req.cid
      clientId.send(fmt(TestHtml).addHeader())

  server(bindAddress = "0.0.0.0", port = 8009):
    routes:
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
          return client.wsServerSend(data.toString(size), WebSocketOpcode.Binary)

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
          return client.wsServerSend(data.toString(size), WebSocketOpcode.Binary)
        of WebSocketOpcode.Ping:
          return client.wsServerSend(data.toString(size), WebSocketOpcode.Pong)
        of WebSocketOpcode.Pong:
          debug "pong ", data.toString(size)
          return SendResult.Success
        else: # WebSocketOpcode.Close
          echo "onClose"
          return SendResult.None

      let urlText = sanitizeHtml(reqUrl)
      return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))

  serverStart()
