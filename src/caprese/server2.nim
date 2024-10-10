# Copyright (c) 2024 zenywallet

echo "welcome server2!"

template addServer*(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped) =
  echo "addServer2"
