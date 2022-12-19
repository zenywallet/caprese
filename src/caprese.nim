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

var configSigTermQuit {.compileTime.}: NimNode = newIdentNode("true")
macro sigTermQuit*(flag: bool) = configSigTermQuit = flag
macro sigTermQuit*: bool = configSigTermQuit

var onSigTermQuitBody {.compileTime.} = newStmtList()
macro onSigTermQuit*(body: untyped) = discard onSigTermQuitBody.add(body)

var configSigPipeIgnore {.compileTime.}: NimNode = newIdentNode("true")
macro sigPipeIgnore*(flag: bool) = configSigPipeIgnore = flag
macro sigPipeIgnore*: bool = configSigPipeIgnore

var configMaxOpenFiles {.compileTime.}: NimNode = newIdentNode("true")
var configLimitOpenFiles {.compileTime.}: NimNode = newIdentNode("65536")
macro limitOpenFiles*(num: int) =
  configMaxOpenFiles = newIdentNode("false")
  configLimitOpenFiles = num

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

proc defaultConfig*(): Config {.compileTime.} =
  result.ssl = true
  result.sslLib = BearSSL
  result.debugLog = false

var cfg* {.compileTime.}: Config = defaultConfig()

macro addCfgDotExpr(body: untyped): untyped =
  var bdy = body
  for i in 0..<bdy.len:
    bdy[i][0] = nnkDotExpr.newTree(
      newIdentNode("cfg"),
      bdy[i][0]
    )
  return bdy

template config*(body: untyped): untyped =
  macro addCfg() =
    addCfgDotExpr(body)
  addCfg()

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

    when `configMaxOpenFiles`:
      setMaxRlimitOpenFiles()
    else:
      setRlimitOpenFiles(`configLimitOpenFiles`)
    when `configSigPipeIgnore`: signal(SIGPIPE, SIG_IGN)
    when `configSigTermQuit`:
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

macro pendingBody(data: auto): untyped =
  quote do:
    proc pendingProc(): SendResult {.discardable.} =
      let cid = client.markPending()
      if reqs.send((cid, `data`)):
        return SendResult.Pending
      else:
        return SendResult.Error

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

  var reqs = newPending[PendingData](limit = 100)

  sigTermQuit: true
  onSigTermQuit:
    reqs.drop()

  sigPipeIgnore: true

  const IndexHtml = staticHtmlDocument:
    buildHtml(html):
      head:
        meta(harset="utf-8")
      body:
        text "welcome"

  const TestHtml = staticHtmlDocument:
    buildHtml(html):
      head:
        meta(harset="utf-8")
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
