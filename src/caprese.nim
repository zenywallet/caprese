# Copyright (c) 2022 zenywallet

when not compileOption("threads"):
  {.error: "requires --threads:on option.".}

when isMainModule:
  {.define: DYNAMIC_FILES.}

import std/macros
import std/nativesockets
import std/os
import caprese/server as serverlib
import caprese/contents
import caprese/files
import caprese/statuscode
import caprese/queue
import caprese/rlimit
import caprese/config
export nativesockets
export os
export serverlib
export contents
export files
export statuscode
export queue
export config

var active* = true
var workerNum = 0

var onSigTermQuitBody {.compileTime.} = newStmtList()
macro onSigTermQuit(body: untyped) = discard onSigTermQuitBody.add(body)

template onQuit*(body: untyped) = onSigTermQuit(body)


var joli_serverStmt {.compileTime.} = newStmtList()

macro joli_addServer*(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped): untyped =
  quote do:
    discard

template joli_serverTmpl(bindAddress, port, unix, ssl: typed, body: untyped) {.dirty.} =
  discard joli_serverStmt.add quote do:
    joli_addServer(`bindAddress`, `port`, `unix`, `ssl`, `body`)

macro joli_addWorker*(num: int, body: untyped): untyped =
  quote do:
    discard

template joli_workerTmpl(num: typed, body: untyped) {.dirty.} =
  discard joli_serverStmt.add quote do:
    joli_addWorker(`num`, `body`)


var initFlag {.compileTime.}: bool
macro init*(): untyped =
  if initFlag: return
  initFlag = true

  quote do:
    serverInit()
    serverTagLib(cfg)

    when cfg.limitOpenFiles < 0:
      setMaxRlimitOpenFiles()
    else:
      const limitOpenFiles = cfg.limitOpenFiles
      setRlimitOpenFiles(limitOpenFiles)
    when cfg.sigPipeIgnore: signal(SIGPIPE, SIG_IGN)
    serverlib.abort = proc() {.thread.} =
      serverlib.serverStop()
      active = false
    when cfg.sigTermQuit:
      onSignal(SIGINT, SIGTERM):
        echo "bye from signal ", sig
        serverlib.abort()
        `onSigTermQuitBody`

macro server*(ssl: bool, ip: string, port: uint16, body: untyped): untyped =
  joli_serverTmpl(ip, port, false, ssl, body)
  discard serverStmt.add quote do:
    init()
    echo "server: ", `ip`, ":", `port`, (if `ssl`: " SSL" else: "")
    addServer(`ip`, `port`, false, `ssl`, `body`)

macro server*(ip: string, port: uint16, body: untyped): untyped =
  joli_serverTmpl(ip, port, false, false, body)
  discard serverStmt.add quote do:
    init()
    echo "server: ", `ip`, ":", `port`
    addServer(`ip`, `port`, false, false, `body`)


macro server*(unix: string, body: untyped): untyped =
  joli_serverTmpl(unix, 0, true, false, body)
  discard serverStmt.add quote do:
    init()
    echo "server: unix:", `unix`
    addServer(`unix`, 0, true, false, `body`)

template serverHttp*(ip: string, body: untyped) =
  server(false, ip, 80, body)

template serverHttps*(ip: string, body: untyped) =
  server(true, ip, 443, body)

var workerThreadWaitProc: seq[proc()]

macro worker*(num: int, body: untyped): untyped =
  joli_workerTmpl(num, body)
  var workerRootBlockBody = nnkStmtList.newTree(
    nnkBlockStmt.newTree(
      newIdentNode("workerRoot"),
      body
    )
  )
  discard serverStmt.add quote do:
    init()
    atomicInc(workerNum, `num`)
    var workerThreads: array[`num`, Thread[void]]
    block:
      proc workerProc() {.thread.} = `workerRootBlockBody`
      for i in 0..<`num`:
        createThread(workerThreads[i], workerProc)
    workerThreadWaitProc.add proc() =
      joinThreads(workerThreads)

template worker*(body: untyped) = worker(1, body)

template workerStart*() =
  when not initServerFlag:
    initCfg()
    serverConfigMacro()
    serverMacro()
  for i in countdown(workerThreadWaitProc.high, 0):
    workerThreadWaitProc[i]()

type
  Pendings*[T] = Queue[tuple[cid: ClientId, data: T]]

template newPending*[T](pendingQueue: var Pendings[T], limit: int) =
  pendingQueue.init(limit)
  onQuit:
    pendingQueue.drop()

macro pendingBody*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], data: T): untyped =
  quote do:
    proc pendingProc(): SendResult {.discardable.} =
      when not declared(client):
        {.error: "ClientId of pending can be ommitted only in server blocks.".}
      let cid = client.markPending()
      if `reqs`.send((cid, `data`)):
        SendResult.Pending
      else:
        SendResult.Error

template pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], data: T): SendResult {.dirty.} =
  block:
    when not declared(client):
      {.error: "ClientId of pending can be ommitted only in server blocks.".}
    pendingBody(reqs, data)
    pendingProc()

proc pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], req: tuple[cid: ClientId, data: T]): SendResult {.inline, discardable.} =
  if reqs.send(req):
    SendResult.Pending
  else:
    SendResult.Error

proc pending*[T](reqs: var Queue[tuple[cid: ClientId, data: T]], cid: ClientId, data: T): SendResult {.inline, discardable.} =
  if reqs.send((cid, data)):
    SendResult.Pending
  else:
    SendResult.Error

template exitWorker*() = break workerRoot

template getPending*(reqs: auto): auto =
  let ret = reqs.recv()
  if not active: exitWorker()
  ret

template recvLoop*(reqs: auto, body: untyped) =
  while true:
    let req {.inject.} = reqs.getPending()
    body

template recvLoop*(reqs: auto, req: untyped, body: untyped) =
  while true:
    let req {.inject.} = reqs.getPending()
    body

template onRecv*(reqs: auto, body: untyped) = recvLoop(reqs, body)

template onRecv*(reqs: auto, req: untyped, body: untyped) = recvLoop(reqs, req, body)


when isMainModule:
  when defined(EXAMPLE1):
    server(ssl = true, ip = "0.0.0.0", port = 8009):
      routes:
        get "/":
          send("Hello!".addHeader())

        send("Not Found".addHeader(Status404))

    serverStart()

  elif defined(EXAMPLE2):
    type
      CipherContext = object
        encryptVector: array[16, byte]
        decryptVector: array[16, byte]
        key: array[140, uint32]

      ClientExt {.clientExt.} = object
        cipherCtx: CipherContext

    proc cipherInit(ctx: var CipherContext) =
      zeroMem(addr ctx, sizeof(CipherContext))
      echo "ctx=", ctx

    server(ssl = true, ip = "0.0.0.0", port = 8009):
      routes:
        stream "/":
          onOpen:
            cipherInit(client.cipherCtx)

        get "/":
          """<script>new WebSocket("wss://localhost:8009")</script>""".addHeader.send

        send("Not Found".addHeader(Status404))

    serverStart()

  elif defined(EXAMPLE3):
    import std/strformat
    import std/re

    type
      PendingData = object
        url: string

    config:
      sslLib = BearSSL
      debugLog = true

      httpHeader:
        HeaderHost: "Host"
        HeaderAcceptEncoding: "Accept-Encoding"
        HeaderConnection: "Connection"

    var reqs: Pendings[PendingData]
    reqs.newPending(limit = 100)

    const IndexHtml = staticHtmlDocument:
      buildHtml(html):
        head:
          meta(charset="utf-8")
        body:
          text "welcome"

    const TestHtml = staticHtmlDocument:
      buildHtml(html):
        head:
          meta(charset="utf-8")
        body:
          text "[worker] {urlText}"

    const WsTestJs = staticScript:
      import jsffi
      import caprese/jslib

      var testDataBase = ""
      var testData = ""
      for i in 0..<100:
        testDataBase = testDataBase & "[testdata]"
      for i in 0..<100:
        testData = testData & testDataBase

      proc wsUrl(domain, path: cstring): cstring =
        var prot = if window.location.protocol == "https:".toJs: "wss:".cstring else: "ws:".cstring
        var port = window.location.port
        var sport = if port == 80.toJs or port == 443.toJs: "".cstring else: ":".cstring & port.to(cstring)
        result = prot & "//".cstring & domain & sport & "/".cstring & path

      var ws = newWebSocket(wsUrl("localhost", "ws"), "caprese-0.1")
      proc testSend() =
        if ws.readyState == WebSocket.OPEN:
          ws.send(testData)
      setInterval(testSend, 3000)

    const WsTestMinJs = scriptMinifier(code = WsTestJs, extern = "")

    const WsTestHtml = staticHtmlDocument:
      buildHtml(html):
        head:
          meta(charset="utf-8")
        body:
          text "websocket test"
          script: verbatim WsTestMinJs

    worker(num = 2):
      reqs.recvLoop(req):
        let urlText = sanitizeHtml(req.data.url)
        let clientId = req.cid
        clientId.send(fmt(TestHtml).addHeader())

    server(ssl = true, ip = "0.0.0.0", port = 8009):
      routes(host = "localhost"):
        certificates(path = "./certs/site_a"):
          privKey: "privkey.pem"
          fullChain: "fullchain.pem"

        # client: Client
        # url: string
        # headers: Headers

        get "/":
          send(IndexHtml.addHeader())

        get "/home", "/main", "/about":
          send(IndexHtml.addHeader())

        get re"/([a-z]+)(\d+)":
          send(sanitizeHtml(matches[0] & "|" & matches[1]).addHeader())

        get "/test":
          reqs.pending(PendingData(url: reqUrl))

        get "/wstest":
          send(WsTestHtml.addHeader())

        when defined(USE_STARTSWITH):
          get startsWith("/user/"):
            send(reqUrl[6..^1].addHeader(mimetype = "text"))
        else:
          get "/user/:username":
            send(sanitizeHtml(username).addHeader(mimetype = "text"))

        stream(path = "/ws", protocol = "caprese-0.1"):
          # client: Client
          onOpen:
            echo "onOpen"

          # client: Client
          # opcode: WebSocketOpCode
          # data: ptr UncheckedArray[byte]
          # size: int
          onMessage:
            echo "onMessage"
            wsSend(data.toString(size), WebSocketOpcode.Binary)

          onClose:
            echo "onClose"

        stream(path = "/ws2", protocol = "caprese-0.1"):
          # client: Client
          onOpen:
            echo "onOpen"

          # client: Client
          # opcode: WebSocketOpCode
          # data: ptr UncheckedArray[byte]
          # size: int
          echo "stream test"
          case opcode
          of WebSocketOpcode.Binary, WebSocketOpcode.Text, WebSocketOpcode.Continue:
            echo "onMessage"
            wsSend(data.toString(size), WebSocketOpcode.Binary)
          of WebSocketOpcode.Ping:
            wsSend(data.toString(size), WebSocketOpcode.Pong)
          of WebSocketOpcode.Pong:
            debug "pong ", data.toString(size)
            SendResult.Success
          else: # WebSocketOpcode.Close
            echo "onClose"
            SendResult.None

        let urlText = sanitizeHtml(reqUrl)
        send(fmt"Not Found: {urlText}".addDocType().addHeader(Status404))

    server(ip = "0.0.0.0", port = 8089):
      routes(host = "localhost"):
        get "/":
          send(IndexHtml.addHeader())

        let urlText = sanitizeHtml(reqUrl)
        send(fmt"Not Found: {urlText}".addDocType().addHeader(Status404))

    serverStart()

  elif defined(BENCHMARK1):
    config:
      sslLib = None
      headerServer = true
      headerDate = true
      activeHeader = true
      connectionPreferred = InternalConnection
      urlRootSafe = false

    server(ip = "0.0.0.0", port = 8089):
      routes:
        get "/": "Hello, World!".addHeader("text").send
        "Not Found".addHeader(Status404, "text").send

    serverStart()

  elif defined(BENCHMARK2):
    config:
      sslLib = None
      headerServer = true
      headerDate = true
      activeHeader = true
      connectionPreferred = ExternalConnection
      urlRootSafe = false

    server(ip = "0.0.0.0", port = 8089):
      routes:
        get "/": "Hello, World!".addHeader("text").send
        "Not Found".addHeader(Status404, "text").send

    serverStart()

  else:
    if paramCount() != 1:
      echo "usage: caprese <public folder>"
      quit(QuitFailure)

    var publicPath = paramStr(1)
    initDynamicFile(publicPath)

    macro envSslFlag(): untyped =
      if os.getEnv("NOSSL") == "1":
        newLit(false)
      else:
        newLit(true)

    const sslFlag = envSslFlag()

    when not sslFlag:
      config:
        sslLib = None

    server(ssl = sslFlag, ip = "127.0.0.1", port = (when sslFlag: 8009 else: 8089)):
      routes(host = "localhost"):
        var fileContentResult = getDynamicFile(reqUrl())
        if fileContentResult.err == FileContentSuccess:
          var fileContent = fileContentResult.data
          return send(fileContent.content.addHeader(EncodingType.None, fileContent.md5, Status200, fileContent.mime))
        return send("Not Found".addHeader(Status404))

    serverStart()
