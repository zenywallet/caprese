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
    activeHeader*: bool
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
  result.activeHeader = false
  result.errorCloseMode = CloseImmediately
  result.connectionPreferred = ExternalConnection
  result.urlRootSafe = true
  result.postRequestMethod = false
  result.sslRoutesHost = SniAndHeaderHost
  result.acceptFirst = false

var defaultConfigStmt* {.compileTime.}: NimNode

macro defaultConfigMacro(body: untyped): untyped =
  defaultConfigStmt = body
  result = nnkObjConstr.newTree(newIdentNode("Config"))
  for i in 0..<body.len:
    if body[i].kind == nnkAsgn:
      result.add(nnkExprColonExpr.newTree(body[i][0], body[i][1]))

const defaultConfig0* = defaultConfigMacro:
  sslLib = BearSSL
  debugLog = false
  sigTermQuit = true
  sigPipeIgnore = true
  limitOpenFiles = -1
  serverWorkerNum = -1
  epollEventsSize = 10
  soKeepalive = false
  tcpNodelay = true
  clientMax = 32000
  connectionTimeout = 120
  recvBufExpandBreakSize = 131072 * 5
  maxFrameSize = 131072 * 5
  certsPath = "./certs"
  privKeyFile = "privkey.pem"
  fullChainFile = "fullchain.pem"
  httpVersion = 1.1
  serverName = "Caprese"
  headerServer = false
  headerDate = false
  headerContentType = true
  activeHeader = false
  errorCloseMode = CloseImmediately
  connectionPreferred = ExternalConnection
  urlRootSafe = true
  postRequestMethod = false
  sslRoutesHost = SniAndHeaderHost
  acceptFirst = false

macro staticBool*(b: static bool): untyped = newLit(b)
macro staticInt*(a: static int): untyped = newLit(a)
macro staticFloat64*(a: static float64): untyped = newLit(a)
macro staticString*(s: static string): untyped = newLit(s)
