# Copyright (c) 2022 zenywallet

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

var configSigTermQuit {.compileTime.}: NimNode
macro sigTermQuit*(flag: bool) = configSigTermQuit = flag
macro sigTermQuit*: bool = configSigTermQuit

var onSigTermQuitBody {.compileTime.} = newStmtList()
var onSigTermQuitBodyFlag {.compileTime.}: bool
macro onSigTermQuit*(body: untyped) = discard onSigTermQuitBody.add(body)
macro sigTermQuitBody(): untyped =
  if onSigTermQuitBodyFlag: return
  onSigTermQuitBodyFlag = true
  quote do:
    when `configSigTermQuit`:
      onSignal(SIGINT, SIGTERM):
        echo "bye from signal ", sig
        server.stop()
        active = false
        `onSigTermQuitBody`

template sigPipeIgnore*(flag: bool) =
  when flag: signal(SIGPIPE, SIG_IGN)

template limitOpenFiles*(num: int) = setRlimitOpenFiles(num)

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

macro server*(bindAddress: string, port: uint16, body: untyped): untyped =
  quote do:
    sigTermQuitBody()
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

template pending*(data: auto): SendResult =
  block:
    pendingBody(data)
    pendingProc()

template getPending*(): auto = reqs.recv()

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
      let req = getPending()
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
        return pending(PendingData(url: url))

      let urlText = sanitizeHtml(url)
      return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))
