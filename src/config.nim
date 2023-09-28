# Copyright (c) 2023 zenywallet

type
  SslLib* = enum
    None
    BearSSL
    OpenSSL
    LibreSSL
    BoringSSL

  Config* = object
    sslLib*: SslLib
    debugLog*: bool
    sigTermQuit*: bool
    sigPipeIgnore*: bool
    limitOpenFiles*: int
    serverWorkerNum*: int
    epollEventsSize*: int
    soKeepalive*: bool
    tcpNodelay*: bool
    clientMax*: int
    connectionTimeout*: int
    recvBufExpandBreakSize*: int
    maxFrameSize*: int
    certsPath*: string
    privKeyFile*: string
    fullChainFile*: string
    httpVersion*: float64
    serverName*: string

proc defaultConfig*(): Config {.compileTime.} =
  result.sslLib = BearSSL
  result.debugLog = false
  result.sigTermQuit = true
  result.sigPipeIgnore = true
  result.limitOpenFiles = -1
  result.serverWorkerNum = -1
  result.epollEventsSize = 10
  result.soKeepalive = false
  result.tcpNodelay = true
  result.clientMax = 32000
  result.connectionTimeout = 120
  result.recvBufExpandBreakSize = 131072 * 5
  result.maxFrameSize = 131072 * 5
  result.certsPath = "./certs"
  result.privKeyFile = "privkey.pem"
  result.fullChainFile = "fullchain.pem"
  result.httpVersion = 1.1
  result.serverName = "Caprese"
