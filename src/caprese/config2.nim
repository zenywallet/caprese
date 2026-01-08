# Copyright (c) 2023 zenywallet

import std/macros
import std/tables

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
    BothUnchecked

  ClientThreadAssign* = enum
    AutoAssign
    DynamicAssign
    FixedAssign

type Config* = object

var configParams {.compileTime.}: Table[string, Table[string, NimNode]]

macro init() =
  configParams = initTable[string, Table[string, NimNode]]()

macro initConfig*(cfg: untyped) =
  var cfgStr = cfg.strVal
  if not configParams.hasKey(cfgStr):
    configParams[cfgStr] = initTable[string, NimNode]()
  else:
    error "config: " & cfgStr & " already exists"

macro getConfig*(cfg, name: untyped): untyped =
  try:
    configParams[cfg.strVal][name.strVal]
  except:
    error "config: unknown " & name.strVal

template `.`*(cfg: Config, field: untyped): auto = cfg.getConfig(field)

template setConfigBody(cfgStr: string, body: untyped) =
  for a in body:
    if a.kind == nnkAsgn:
      configParams[cfgStr][a[0].strVal] = a[1]

macro config*(body: untyped) = setConfigBody("cfg", body)

macro config*(cfg, body: untyped) = setConfigBody(cfg.strVal, body)

macro setDefault(cfg: untyped) =
  var body = quote do:
    sslLib = BearSSL
    debugLog = false
    sigTermQuit = true
    sigPipeIgnore = true
    limitOpenFiles = -1
    serverWorkerNum = -1
    eventsSize = 10
    soKeepalive = false
    tcpNodelay = true
    clientMax = 32000
    connectionTimeout = 120
    recvBufExpand = true
    recvBufExpandBreakSize = 131072 * 5
    sendBufExpand = true
    sendBufExpandBreakSize = -1
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
    reusePort = false
    multiProcess = false
    multiProcessThreadNum = 1
    clientThreadAssign = AutoAssign
    clientLock = true
    reqHeaderConnection = false

  setConfigBody(cfg.strVal, body)

template defaultConfig*(cfg: Config) = setDefault(cfg)

init()

var cfg*: Config
initConfig(cfg)
defaultConfig(cfg)


when isMainModule:
  echo cfg.sslLib

  config:
    sslLib = OpenSSL
    test = "test"

  echo cfg.sslLib
  echo cfg.test

  var cfg2: Config
  initConfig(cfg2)
  defaultConfig(cfg2)

  config(cfg2):
    sslLib = LibreSSL

  echo cfg.sslLib, " ", cfg2.sslLib
