# Copyright (c) 2022 zenywallet

import posix
import server
import contents
import queue


when isMainModule:
  var active = true
  var reqs: Queue[tuple[cid: ClientId, url: string]]
  reqs.init(100)

  onSignal(SIGINT, SIGTERM):
    echo "bye from signal ", sig
    server.stop()
    active = false
    reqs.send((INVALID_CLIENT_ID, cast[string](nil)))

  signal(SIGPIPE, SIG_IGN)

  setRlimitOpenFiles(RLIMIT_OPEN_FILES)

  var workerThread: Thread[void]

  proc worker() {.thread.} =
    while true:
      var req = reqs.recv()
      if not active: break
      var content = "<!DOCTYPE html><meta charset=\"utf-8\">[worker] " & req.url
      let clientId = req.cid
      discard clientId.send(content.addHeader())

  createThread(workerThread, worker)

  proc webMain(client: ptr Client, url: string, headers: Headers): SendResult =
    if url == "/test":
      var cid = client.markPending()
      reqs.send((cid, url))
      return SendResult.Pending

    var content = "<!DOCTYPE html><meta charset=\"utf-8\">" & url
    return client.send(content.addHeader())

  setWebMain(webMain)

  start()
