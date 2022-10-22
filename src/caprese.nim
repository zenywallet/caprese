# Copyright (c) 2022 zenywallet

import posix
import server
import contents
import queue

var active* = true

template pendingLimit*(limit: int) {.dirty.} =
  var reqs: Queue[tuple[cid: ClientId, data: PendingData]]
  reqs.init(limit)

template sigTermQuit*(flag: bool) =
  when flag:
    onSignal(SIGINT, SIGTERM):
      echo "bye from signal ", sig
      server.stop()
      active = false
      var emptyData: PendingData
      reqs.send((INVALID_CLIENT_ID, emptyData))

template sigPipeIgnore*(flag: bool) =
  when flag: signal(SIGPIPE, SIG_IGN)


when isMainModule:
  type
    PendingData = object
      url: string

  pendingLimit: 100
  sigTermQuit: true
  sigPipeIgnore: true

  setRlimitOpenFiles(RLIMIT_OPEN_FILES)

  var workerThread: Thread[void]

  proc worker() {.thread.} =
    while true:
      var req = reqs.recv()
      if not active: break
      var content = "<!DOCTYPE html><meta charset=\"utf-8\">[worker] " & req.data.url
      let clientId = req.cid
      discard clientId.send(content.addHeader())

  createThread(workerThread, worker)

  proc webMain(client: ptr Client, url: string, headers: Headers): SendResult =
    if url == "/test":
      var cid = client.markPending()
      reqs.send((cid, PendingData(url: url)))
      return SendResult.Pending

    var content = "<!DOCTYPE html><meta charset=\"utf-8\">" & url
    return client.send(content.addHeader())

  setWebMain(webMain)

  start()
