# Copyright (c) 2023 zenywallet

import macros

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

paramNamesConst("configNames")

var defaultConfigStmt* {.compileTime.}: NimNode

macro defaultConfigMacro(body: untyped): untyped =
  defaultConfigStmt = body
  result = nnkObjConstr.newTree(newIdentNode("Config"))
  for i in 0..<body.len:
    if body[i].kind == nnkAsgn:
      result.add(nnkExprColonExpr.newTree(body[i][0], body[i][1]))

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
macro staticConfig(cfg: static Config): untyped =
  result = nnkObjConstr.newTree(newIdentNode("Config"))
  var p = parseExpr($cfg)
  for expr in p:
    result.add(expr)
