# Copyright (c) 2023 zenywallet

import macros

type
  SslLib* = enum
    None
    BearSSL
    OpenSSL
    LibreSSL
    BoringSSL

  ErrorCloseMode* = enum
    CloseImmediately
    UntilConnectionTimeout

  ConnectionPreferred* = enum
    ExternalConnection
    InternalConnection

  SslRoutesHost* = enum
    SniAndHeaderHost
    SniOnly
    HeaderHostOnly

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
    headerServer*: bool
    headerDate*: bool
    headerContentType*: bool
    errorCloseMode*: ErrorCloseMode
    connectionPreferred*: ConnectionPreferred
    urlRootSafe*: bool
    postRequestMethod*: bool
    sslRoutesHost*: SslRoutesHost
    acceptFirst*: bool

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
  result.headerServer = false
  result.headerDate = false
  result.headerContentType = true
  result.errorCloseMode = CloseImmediately
  result.connectionPreferred = ExternalConnection
  result.urlRootSafe = true
  result.postRequestMethod = false
  result.sslRoutesHost = SniAndHeaderHost
  result.acceptFirst = false

macro staticBool*(b: static bool): untyped = newLit(b)
macro staticInt*(a: static int): untyped = newLit(a)
macro staticFloat64*(a: static float64): untyped = newLit(a)
macro staticString*(s: static string): untyped = newLit(s)
