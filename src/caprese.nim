# Copyright (c) 2022 zenywallet

when not compileOption("threads"):
  {.error: "requires --threads:on option.".}

import posix
import serverdef
import contents
import statuscode
import queue
import macros
export serverdef
export contents
export statuscode
export queue

var active* = true
var workerNum = 0

var onSigTermQuitBody {.compileTime.} = newStmtList()
macro onSigTermQuit*(body: untyped) = discard onSigTermQuitBody.add(body)

type
  SslLib* = enum
    BearSSL
    OpenSSL
    LibreSSL
    BoringSSL

  Config* = object
    ssl*: bool
    sslLib*: SslLib
    debugLog*: bool
    sigTermQuit*: bool
    sigPipeIgnore*: bool
    maxOpenFiles*: bool
    limitOpenFiles*: int

proc defaultConfig*(): Config {.compileTime.} =
  result.ssl = true
  result.sslLib = BearSSL
  result.debugLog = false
  result.sigTermQuit = true
  result.sigPipeIgnore = true
  result.maxOpenFiles = true
  result.limitOpenFiles = 65536

var cfg* {.compileTime.}: Config = defaultConfig()

macro addCfgDotExpr(body: untyped): untyped =
  result = nnkStmtList.newTree()
  for i in 0..<body.len:
    if body[i].kind == nnkAsgn:
      var a = body[i]
      a[0] = nnkDotExpr.newTree(
        newIdentNode("cfg"),
        a[0]
      )
      result.add(a)

macro configCalls(body: untyped): untyped =
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

template config*(body: untyped) =
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
    when cfg.sigTermQuit:
      onSignal(SIGINT, SIGTERM):
        echo "bye from signal ", sig
        serverlib.stop()
        active = false
        `onSigTermQuitBody`

macro get*(url: string, body: untyped): untyped =
  quote do:
    if url == `url`:
      `body`

template serverStart(body: untyped) {.dirty.} =
  proc webMain(client: ptr Client, url: string, headers: Headers): SendResult =
    body
  setWebMain(webMain)

macro routes*(body: untyped): untyped =
  quote do:
    serverStart(`body`)

template setStream(body: untyped) {.dirty.} =
  proc streamMain(client: ptr Client, opcode: WebSocketOpCode,
                  data: ptr UncheckedArray[byte], size: int): SendResult =
    body
  setStreamMain(streamMain)

macro stream*(body: untyped): untyped =
  quote do:
    setStream(`body`)

macro server*(bindAddress: string, port: uint16, body: untyped): untyped =
  quote do:
    init()
    echo "bind address: ", `bindAddress`
    echo "port: ", `port`
    `body`
    start()

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

macro pendingBody[T](reqs: var Queue[tuple[cid: ClientId, data: T]], data: T): untyped =
  quote do:
    proc pendingProc(): SendResult {.discardable.} =
      when not declared(client):
        {.error: "ClientId of pending can be ommitted only in server blocks.".}
      let cid = client.markPending()
      if `reqs`.send((cid, `data`)):
        return SendResult.Pending
      else:
        return SendResult.Error

template pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], data: T): SendResult =
  block:
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

template send*(data: string): SendResult = client.send(data)


when isMainModule:
  import strformat

  type
    PendingData = object
      url: string

  config:
    ssl = true
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

  worker(num = 2):
    while true:
      let req = reqs.getPending()
      let urlText = sanitizeHtml(req.data.url)
      let clientId = req.cid
      clientId.send(fmt(TestHtml).addHeader())

  server(bindAddress = "0.0.0.0", port = 8009):
    routes:
      # client: ptr Client
      # url: string
      # headers: Headers

      get "/":
        return send(IndexHtml.addHeader())

      get "/test":
        return reqs.pending(PendingData(url: url))

      let urlText = sanitizeHtml(url)
      return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))

    stream:
      # client: ptr Client
      # opcode: WebSocketOpCode
      # data: ptr UncheckedArray[byte]
      # size: int

      echo "opcode=", opcode
