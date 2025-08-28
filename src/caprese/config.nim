# Copyright (c) 2023 zenywallet

import std/macros
import std/os

var paramNamesStmt {.compileTime.} = newStmtList()

proc findNodeKind(n: NimNode; nodeKind: NimNodeKind): NimNode {.compileTime.} =
  var res: NimNode
  for c in n.children:
    var ret = findNodeKind(c, nodeKind)
    if ret.kind != nnkNilLit:
      return ret
    if c.kind == nodeKind:
      res = c
      break
  res

macro paramNames*(constName: string; body: untyped): untyped =
  var param = ident($constName)
  var recList = findNodeKind(body, nnkRecList)
  var bracket = nnkBracket.newTree()
  for d in recList:
    if d.kind == nnkIdentDefs:
      var n = d[0]
      if n.len > 0:
        n = n[n.len - 1]
      bracket.add(newLit($n))
  paramNamesStmt.add quote do:
    const `param` = `bracket`
  body

macro paramNamesConst*(): untyped = paramNamesStmt

macro paramNamesConst*(paramName: string): untyped =
  result = newStmtList()
  for n in paramNamesStmt:
    if $n[0][0] == $paramName:
      result.add(n)

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

  Config* {.paramNames: "configNames".} = object
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
    recvBufExpand*: bool
    recvBufExpandBreakSize*: int
    sendBufExpand*: bool
    sendBufExpandBreakSize*: int
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
    reusePort*: bool
    multiProcess*: bool
    multiProcessThreadNum*: int
    clientThreadAssign*: ClientThreadAssign
    clientLock*: bool
    reqHeaderConnection*: bool

paramNamesConst("configNames")

var cfgNode {.compileTime.}: NimNode

var defaultConfigStmt* {.compileTime.}: NimNode

macro defaultConfigMacro(body: untyped): untyped =
  defaultConfigStmt = body
  result = nnkObjConstr.newTree(newIdentNode("Config"))
  for n in body:
    if n.kind == nnkAsgn:
      result.add(nnkExprColonExpr.newTree(n[0], n[1]))
  cfgNode = result

const defaultConfig* = defaultConfigMacro:
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

var configStmt* {.compileTime.} = newStmtList()

macro httpHeader*(body: untyped): untyped = quote do: discard

macro updateCfgNode(cfg: static Config) =
  var cfgNodeTmp = nnkObjConstr.newTree(newIdentNode("Config"))
  var p = parseExpr($cfg)
  for expr in p:
    cfgNodeTmp.add(expr)
  cfgNode = cfgNodeTmp

macro getConfig*(): untyped = cfgNode

template cfg*: Config = getConfig()

macro config*(body: untyped): untyped =
  for n in body:
    configStmt.add(n)
  var cfgTmp = genSym(nskVar, "cfg")
  var bodyTmp = body
  proc parseChange(n: NimNode) =
    for i in 0..<n.len:
      parseChange(n[i])
      if n.kind == nnkStmtList and n[i].kind == nnkAsgn:
        var n0 = n[i][0]
        if $n0 in configNames:
          var n1 = n[i][1]
          n[i] = nnkAsgn.newTree(nnkDotExpr.newTree(cfgTmp, n0), n1)
  parseChange(bodyTmp)
  var cfgNodeTmp = quote do:
    block:
      var `cfgTmp` = `cfgNode`
      `bodyTmp`
      `cfgTmp`
  var retConfig = genSym(nskProc, "retConfig")
  quote do:
    updateCfgNode(`cfgNodeTmp`)
    proc `retConfig`(): Config {.discardable.} = getConfig()
    `retConfig`()

macro noSslForceSet*(): untyped =
  var setNossl = fileExists(currentSourcePath.parentDir() / "../lib/NOSSL.a")
  if setNossl:
    var cfgNodeTmp = cfgNode.copy()
    for i in 0..<cfgNodeTmp.len:
      if cfgNodeTmp[i].kind == nnkExprColonExpr:
        if $cfgNodeTmp[i][0] == "sslLib" and $cfgNodeTmp[i][1] != "None":
          cfgNodeTmp[i][1] = newIdentNode("None")
          hint("NOSSL mode is set")
    quote do:
      updateCfgNode(`cfgNodeTmp`)
  else:
    newEmptyNode()

macro staticBool*(b: static bool): untyped = newLit(b)
macro staticInt*(a: static int): untyped = newLit(a)
macro staticFloat64*(a: static float64): untyped = newLit(a)
macro staticString*(s: static string): untyped = newLit(s)
macro staticConfig*(cfg: static Config): untyped =
  result = nnkObjConstr.newTree(newIdentNode("Config"))
  var p = parseExpr($cfg)
  for expr in p:
    result.add(expr)

macro evalSslLib*(val: SslLib): SslLib =
  quote do:
    when `val` == BearSSL: BearSSL
    elif `val` == OpenSSL: OpenSSL
    elif `val` == LibreSSL: LibreSSL
    elif `val` == BoringSSL: BoringSSL
    else: None
