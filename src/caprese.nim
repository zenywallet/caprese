# Copyright (c) 2022 zenywallet

import posix
import server
import contents
import statuscode
import queue
import macros

var active* = true
var workerNum = 0

template pendingLimit*(limit: int) {.dirty.} =
  var reqs: Queue[tuple[cid: ClientId, data: PendingData]]
  reqs.init(limit)

template sigTermQuit*(flag: bool) =
  when flag:
    onSignal(SIGINT, SIGTERM):
      echo "bye from signal ", sig
      server.stop()
      active = false
      for i in 0..<workerNum:
        var emptyData: PendingData
        reqs.send((INVALID_CLIENT_ID, emptyData))

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
  start()

macro server*(bindAddress: string, port: uint16, body: untyped): untyped =
  quote do:
    echo "bind address: ", `bindAddress`
    echo "port: ", `port`
    serverStart(`body`)

macro worker*(num: int, body: untyped): untyped =
  quote do:
    atomicInc(workerNum, `num`)
    var workerThreads: array[`num`, Thread[void]]
    block:
      proc workerProc() {.thread.} = `body`
      for i in 0..<`num`:
        createThread(workerThreads[i], workerProc)

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
  type
    PendingData = object
      url: string

  pendingLimit: 100
  sigTermQuit: true
  sigPipeIgnore: true
  limitOpenFiles: 65536

  worker(num = 2):
    while true:
      let req = getPending()
      if not active: break
      let content = """<!DOCTYPE html><meta charset="utf-8">[worker] """ & req.data.url
      let clientId = req.cid
      clientId.send(content.addHeader())

  server(bindAddress = "0.0.0.0", port = 8009):
    get "/":
      return send("""<!DOCTYPE html><meta charset="utf-8">welcome""".addHeader())

    get "/test":
      return pending(PendingData(url: url))

    let notFound = """<!DOCTYPE html><meta charset="utf-8">Not found: """ & url
    return send(notFound.addHeader(Status404))
