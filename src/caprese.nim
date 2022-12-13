# Copyright (c) 2022 zenywallet

when not compileOption("threads"):
  {.error: "requires --threads:on option.".}

import posix
import server
import contents
import statuscode
import queue
import macros
export server
export contents
export statuscode
export queue

var active* = true
var workerNum = 0

var configPendingLimit {.compileTime.}: NimNode
macro pendingLimit*(limit: int) = configPendingLimit = limit
macro pendingLimit*: int = configPendingLimit

var configSigTermQuit {.compileTime.}: NimNode = newIdentNode("true")
macro sigTermQuit*(flag: bool) = configSigTermQuit = flag
macro sigTermQuit*: bool = configSigTermQuit

var onSigTermQuitBody {.compileTime.} = newStmtList()
macro onSigTermQuit*(body: untyped) = discard onSigTermQuitBody.add(body)

var configSigPipeIgnore {.compileTime.}: NimNode = newIdentNode("true")
macro sigPipeIgnore*(flag: bool) = configSigPipeIgnore = flag
macro sigPipeIgnore*: bool = configSigPipeIgnore

template limitOpenFiles*(num: int) = setRlimitOpenFiles(num)

var initFlag {.compileTime.}: bool
macro init(): untyped =
  if initFlag: return
  initFlag = true
  quote do:
    when `configSigPipeIgnore`: signal(SIGPIPE, SIG_IGN)
    when `configSigTermQuit`:
      onSignal(SIGINT, SIGTERM):
        echo "bye from signal ", sig
        server.stop()
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
  quote do:
    atomicInc(workerNum, `num`)
    var workerThreads: array[`num`, Thread[void]]
    block:
      proc workerProc() {.thread.} = `body`
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

template getPending*(reqs: auto): auto = reqs.recv()

template send*(data: string): SendResult = client.send(data)


when isMainModule:
  import strformat

  type
    PendingData = object
      url: string

  pendingLimit: 100
  var reqs = newPending[PendingData](limit = pendingLimit)

  sigTermQuit: true
  onSigTermQuit:
    reqs.drop()

  sigPipeIgnore: true
  limitOpenFiles: 65536

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
      if not active: break
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
