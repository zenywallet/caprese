# Copyright (c) 2022 zenywallet

import posix
import server
import contents


when isMainModule:
  onSignal(SIGINT, SIGTERM):
    echo "bye from signal ", sig
    server.stop()

  signal(SIGPIPE, SIG_IGN)

  setRlimitOpenFiles(RLIMIT_OPEN_FILES)

  proc webMain(client: ptr Client, url: string, headers: Headers): SendResult =
    var content = "<!DOCTYPE html><meta charset=\"utf-8\">" & url
    return client.send(content.addHeader())

  setWebMain(webMain)

  start()
