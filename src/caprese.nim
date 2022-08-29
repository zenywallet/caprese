# Copyright (c) 2022 zenywallet

import posix
import server


when isMainModule:
  onSignal(SIGINT, SIGTERM):
    echo "bye from signal ", sig
    server.stop()

  signal(SIGPIPE, SIG_IGN)

  setRlimitOpenFiles(RLIMIT_SIZE)
  start()
