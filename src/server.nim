# Copyright (c) 2021 zenywallet

import std/macros
import std/nativesockets
import std/posix
import std/sha1
import std/base64
import std/cpuinfo
import std/os
import std/strutils
import logs
import arraylib

type
  ClientId* = int

  SendResult* {.pure.} = enum
    Error = -1
    None = 0
    Success = 1
    Pending = 2
    Invalid = 3

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
    recvBufExpandBreakSize*: int
    maxFrameSize*: int
    certsPath*: string
    privKeyFile*: string
    fullChainFile*: string

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
  result.recvBufExpandBreakSize = 131072 * 5
  result.maxFrameSize = 131072 * 5
  result.certsPath = "./certs"
  result.privKeyFile = "privkey.pem"
  result.fullChainFile = "fullchain.pem"

macro HttpTargetHeader(idEnumName, valListName, targetHeaders, body: untyped): untyped =
  var enumParams = nnkEnumTy.newTree(newEmptyNode())
  var targetParams = nnkBracket.newTree()
  var headers = nnkBracket.newTree()
  var internalEssentialHeaders = @[("InternalEssentialHeaderHost", "Host"),
                                  ("InternalEssentialHeaderConnection", "Connection"),
                                  ("InternalSecWebSocketKey", "Sec-WebSocket-Key"),
                                  ("InternalSecWebSocketProtocol", "Sec-WebSocket-Protocol"),
                                  ("InternalSecWebSocketVersion", "Sec-WebSocket-Version"),
                                  ("InternalAcceptEncoding", "Accept-Encoding"),
                                  ("InternalIfNoneMatch", "If-None-Match")]
  var internalEssentialConst = nnkStmtList.newTree()

  for a in body:
    enumParams.add(a[0])
    var paramLit = newLit($a[1][0] & ": ")
    targetParams.add(paramLit)
    headers.add(nnkTupleConstr.newTree(
      nnkExprColonExpr.newTree(
        newIdentNode("id"),
        a[0]
      ),
      nnkExprColonExpr.newTree(
        newIdentNode("val"),
        paramLit
      )
    ))

  for a in body:
    for i, b in internalEssentialHeaders:
      if $a[1][0] == b[1]:
        internalEssentialConst.add(
          nnkConstSection.newTree(
            nnkConstDef.newTree(
              newIdentNode(b[0]),
              newEmptyNode(),
              newIdentNode($a[0])
            )
          ))
        internalEssentialHeaders.delete(i)
        break

  for b in internalEssentialHeaders:
    enumParams.add(newIdentNode(b[0]))
    var compareVal = b[1] & ": "
    targetParams.add(newLit(compareVal))
    headers.add(nnkTupleConstr.newTree(
      nnkExprColonExpr.newTree(
        newIdentNode("id"),
        newIdentNode(b[0])
      ),
      nnkExprColonExpr.newTree(
        newIdentNode("val"),
        newLit(compareVal)
      )
    ))

  nnkStmtList.newTree(
    nnkTypeSection.newTree(
      nnkTypeDef.newTree(
        idEnumName,
        newEmptyNode(),
        enumParams
      )
    ),
    internalEssentialConst,
    nnkConstSection.newTree(
      nnkConstDef.newTree(
        valListName,
        newEmptyNode(),
        targetParams
      )
    ),
    nnkVarSection.newTree(
      nnkIdentDefs.newTree(
        targetHeaders,
        newEmptyNode(),
        nnkPrefix.newTree(
          newIdentNode("@^"),
          headers
        )
      )
    )
  )

macro HttpTargetHeader*(body: untyped): untyped =
  quote do:
    HttpTargetHeader(HeaderParams, TargetHeaderParams, TargetHeaders, `body`)

template serverInit*() {.dirty.} =
  import std/epoll
  import std/locks
  import ptlock
  import logs

  when cfg.sslLib == BearSSL:
    {.define: USE_BEARSSL.}
  elif cfg.sslLib == OpenSSL:
    {.define: USE_OPENSSL.}
  elif cfg.sslLib == LibreSSL:
    {.define: USE_LIBRESSL.}
  elif cfg.sslLib == BoringSSL:
    {.define: USE_BORINGSSL.}

  when cfg.sslLib == BearSSL:
    debug "SSL: BearSSL"
    import bearssl/bearssl_ssl
    import bearssl/bearssl_x509
    import bearssl/bearssl_rsa
    import bearssl/bearssl_ec
    import bearssl/bearssl_hash
    import bearssl/bearssl_prf
    import bearssl/bearssl_pem
    when defined(BEARSSL_DEFAULT_EC):
      import bearssl/chain_ec
      import bearssl/key_ec
    else:
      import bearssl/chain_rsa
      import bearssl/key_rsa

  elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
    const sslLib = $cfg.sslLib
    debug "SSL: " & sslLib
    import openssl

  type
    ClientSendProc = proc (client: Client, data: ptr UncheckedArray[byte], size: int): SendResult {.thread.}

    ClientBase* = ref object of RootObj
      sock*: SocketHandle
      recvBuf: ptr UncheckedArray[byte]
      recvBufSize: int
      recvCurSize: int
      sendBuf: ptr UncheckedArray[byte]
      sendCurSize: int
      keepAlive: bool
      ip: uint32
      invoke: bool
      lock: Lock
      spinLock: SpinLock
      whackaMole: bool
      sendProc: ClientSendProc
      ev: EpollEvent
      clientId*: ClientId
      threadId*: int
      srvId*: int
      appId*: int
      appShift: bool
      listenFlag*: bool
      dirty: bool

    ClientObj* = object of ClientBase
      payloadSize: int
      when cfg.sslLib == BearSSL:
        sc: ptr br_ssl_server_context
        keyType: cint
      elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
        ssl: SSL
        sslErr: int
      pStream*: pointer

    Client* = ptr ClientObj

type
  WebSocketOpCode* = enum
    Continue = 0x0
    Text = 0x1
    Binary = 0x2
    Close = 0x8
    Ping = 0x9
    Pong = 0xa

#[
  WebMainCallback* = proc (client: Client, url: string, headers: Headers): SendResult {.thread.}

  StreamMainCallback* = proc (client: Client, opcode: WebSocketOpCode,
                              data: ptr UncheckedArray[byte], size: int): SendResult {.thread.}
]#

  ThreadArgType* {.pure.} = enum
    Void
    WorkerParams

  ThreadArg* = object
    case type*: ThreadArgType
    of ThreadArgType.Void:
      discard
    of ThreadArgType.WorkerParams:
      workerParams*: tuple[threadId: int, bufLen: int]

  ServerError* = object of CatchableError
  #ServerNeedRestartError* = object of CatchableError
  ServerSslCertError* = object of CatchableError

template errorRaise*(x: varargs[string, `$`]) = errorException(x, ServerError)

template errorQuit*(x: varargs[string, `$`]) =
  logs.error(x)
  quit(QuitFailure)

proc toWebSocketOpCode*(opcode: int8): WebSocketOpCode =
  case opcode
  of 0x2: WebSocketOpcode.Binary
  of 0x0: WebSocketOpcode.Continue
  of 0x8: WebSocketOpcode.Close
  of 0x1: WebSocketOpcode.Text
  of 0x9: WebSocketOpcode.Ping
  of 0xa: WebSocketOpcode.Pong
  else: raise

template reallocClientBuf*(buf: ptr UncheckedArray[byte], size: int): ptr UncheckedArray[byte] =
  cast[ptr UncheckedArray[byte]](reallocShared(buf, size))

#[
proc send*(client: Client, data: seq[byte] | string | Array[byte]): SendResult =
  if client.sendCurSize > 0:
    client.addSendBuf(data)
    return SendResult.Pending

  var sendRet: int
  var pos = 0
  var size = data.len
  while true:
    var d = cast[cstring](unsafeAddr data[pos])
    when ENABLE_SSL:
      if not client.ssl.isNil:
        sendRet = client.ssl.SSL_write(d, size.cint)
      else:
        sendRet = client.sock.send(d, size.cint, 0'i32)
    else:
      sendRet = client.sock.send(d, size.cint, 0'i32)
    if sendRet == size:
      return SendResult.Success
    elif sendRet > 0:
      debug "send sendRet=", sendRet, " size=", size
      size = size - sendRet
      pos = pos + sendRet
      continue
    elif sendRet < 0:
      when ENABLE_SSL:
        if not client.ssl.isNil:
          client.sslErr = SSL_get_error(client.ssl, sendRet.cint)
          debug "SSL_send err=", client.sslErr, " errno=", errno
          if client.sslErr == SSL_ERROR_WANT_WRITE or client.sslErr == SSL_ERROR_WANT_READ:
            if pos > 0:
              client.addSendBuf(data[pos..^1])
            else:
              client.addSendBuf(data)
            return SendResult.Pending
          else:
            if errno == EINTR:
              continue
          return SendResult.Error

      if errno == EAGAIN or errno == EWOULDBLOCK:
        if pos > 0:
          client.addSendBuf(data[pos..^1])
        else:
          client.addSendBuf(data)
        return SendResult.Pending
      if errno == EINTR:
        continue
      return SendResult.Error
    else:
      return SendResult.None
]#

var active = true
#var restartFlag = false
#var abortFlag = false
#var serverSock: SocketHandle = osInvalidSocket
#var httpSock: SocketHandle = osInvalidSocket
#var clIdx = 0
#var events: array[EPOLL_EVENTS_SIZE, EpollEvent]
var epfd*: cint = -1

#[
type
  WorkerChannelParam = tuple[appId: int, idx: int, events: uint32, evData: uint64]
var workerChannelWaitingCount: int = 0
var workerQueue: queue.Queue[WorkerChannelParam]
workerQueue.init(WORKER_QUEUE_LIMIT)
]#

type
  WrapperThreadArg = tuple[threadFunc: proc (arg: ThreadArg) {.thread.}, arg: ThreadArg]
#[
var workerThreads: array[WORKER_THREAD_NUM, Thread[WrapperThreadArg]]

var dispatcherThread: Thread[WrapperThreadArg]
var acceptThread: Thread[WrapperThreadArg]
var httpThread: Thread[WrapperThreadArg]
var monitorThread: Thread[WrapperThreadArg]
when ENABLE_SSL and SSL_AUTO_RELOAD:
  var fileWatcherThread: Thread[WrapperThreadArg]
var mainThread: Thread[WrapperThreadArg]
]#

proc getErrnoStr*(): string =
  case errno
  of EADDRINUSE: "errno=EADDRINUSE(" & $errno & ")"
  else: "errno=" & $errno

template serverTagLib*(cfg: static Config) {.dirty.} =
  import std/nativesockets
  import std/posix
  import arraylib
  import bytes
  import hashtable
  import logs

  type
    Tag* = Array[byte]

    TagRef* = object
      tag: ptr Tag
      idx: int

    ClientTaskCmd* {.pure.} = enum
      None
      Data

    ClientTask* = object
      case cmd*: ClientTaskCmd
      of ClientTaskCmd.None:
        discard
      of ClientTaskCmd.Data:
        data*: Array[byte]

  proc toUint64(tag: Tag): uint64 = tag.toSeq.toUint64

  proc empty*(pair: HashTableData): bool =
    when pair.val is Array:
      pair.val.len == 0
    else:
      pair.val == nil
  proc setEmpty*(pair: HashTableData) =
    when pair.val is Array:
      pair.val.empty()
    else:
      pair.val = nil
  loadHashTableModules()
  var pendingClients*: HashTableMem[ClientId, Client]
  var clientsLock*: RWLock
  var curClientId: ClientId = 0
  const INVALID_CLIENT_ID* = 0.ClientId

  var tag2ClientIds*: HashTableMem[Tag, Array[ClientId]]
  var clientId2Tags*: HashTableMem[ClientId, Array[TagRef]]
  var clientId2Tasks*: HashTableMem[ClientId, Array[ClientTask]]

  proc markPending*(client: Client): ClientId {.discardable.} =
    withWriteLock clientsLock:
      while true:
        inc(curClientId)
        if curClientId >= int.high:
          curClientId = 1
        let cur = pendingClients.get(curClientId)
        if cur.isNil:
          break
      client.clientId = curClientId
      pendingClients.set(curClientId, client)
      result = curClientId

  proc unmarkPending*(clientId: ClientId) =
    withWriteLock clientsLock:
      let pair = pendingClients.get(clientId)
      if not pair.isNil:
        let client = pair.val
        pendingClients.del(pair)
        client.clientId = INVALID_CLIENT_ID

  proc unmarkPending*(client: Client) =
    withWriteLock clientsLock:
      pendingClients.del(client.clientId)
      client.clientId = INVALID_CLIENT_ID

  proc setTag*(clientId: ClientId, tag: Tag) =
    withWriteLock clientsLock:
      var tagRefsPair = clientId2Tags.get(clientId)
      var clientIdsPair = tag2ClientIds.get(tag)

      template checkFirstTagAndReturn() {.dirty.} =
        if clientIdsPair.isNil:
          clientIdsPair = tag2ClientIds.set(tag, @^[ClientId clientId])
          tagRefsPair.val.add(TagRef(tag: clientIdsPair.key.addr, idx: 0))
          return

      if tagRefsPair.isNil:
        var emptyTagRef: Array[TagRef]
        tagRefsPair = clientId2Tags.set(clientId, emptyTagRef)

        checkFirstTagAndReturn()
      else:
        checkFirstTagAndReturn()

        for t in tagRefsPair.val:
          if clientIdsPair.key.addr == t.tag:
            return

      clientIdsPair.val.add(clientId)
      tagRefsPair.val.add(TagRef(tag: clientIdsPair.key.addr, idx: clientIdsPair.val.high))

  proc delTag*(clientId: ClientId, tag: Tag) =
    withWriteLock clientsLock:
      let tagRefsPair = clientId2Tags.get(clientId)
      if tagRefsPair.isNil: return
      let clientIdsPair = tag2ClientIds.get(tag)
      if clientIdsPair.isNil: return

      for i, t in tagRefsPair.val:
        if clientIdsPair.key.addr == t.tag:
          if clientIdsPair.val.len <= 1:
            tag2ClientIds.del(clientIdsPair)
          else:
            let lastIdx = clientIdsPair.val.high
            if t.idx != lastIdx:
              let lastClientIdTagsPair = clientId2Tags.get(clientIdsPair.val[lastIdx])
              for j, last in lastClientIdTagsPair.val:
                if clientIdsPair.key.addr == last.tag:
                  lastClientIdTagsPair.val[j].idx = t.idx
                  break
            clientIdsPair.val.del(t.idx)

          if tagRefsPair.val.len <= 1:
            clientId2Tags.del(tagRefsPair)
          else:
            tagRefsPair.val.del(i)
          return

  proc delTags*(clientId: ClientId) =
    withWriteLock clientsLock:
      let tagRefsPair = clientId2Tags.get(clientId)
      if tagRefsPair.isNil: return
      for t in tagRefsPair.val:
        let clientIdsPair = tag2ClientIds.get(t.tag[])
        if clientIdsPair.val.len <= 1:
          tag2ClientIds.del(clientIdsPair)
        else:
          let lastIdx = clientIdsPair.val.high
          if t.idx != lastIdx:
            let lastClientIdTagsPair = clientId2Tags.get(clientIdsPair.val[lastIdx])
            for j, last in lastClientIdTagsPair.val:
              if clientIdsPair.key.addr == last.tag:
                lastClientIdTagsPair.val[j].idx = t.idx
                break
          clientIdsPair.val.del(t.idx)
      clientId2Tags.del(tagRefsPair)

  proc delTags*(tag: Tag) =
    withWriteLock clientsLock:
      let clientIdsPair = tag2ClientIds.get(tag)
      if clientIdsPair.isNil: return
      for clientId in clientIdsPair.val:
        let tagRefsPair = clientId2Tags.get(clientId)
        for i, t in tagRefsPair.val:
          if clientIdsPair.key.addr == t.tag:
            if tagRefsPair.val.len <= 1:
              clientId2Tags.del(tagRefsPair)
            else:
              tagRefsPair.val.del(i)
            break
      tag2ClientIds.del(clientIdsPair)

  proc getClientIds*(tag: Tag): Array[ClientId] =
    withReadLock clientsLock:
      let clientIds = tag2ClientIds.get(tag)
      if not clientIds.isNil:
        result = clientIds.val

  proc getTags*(clientId: ClientId): Array[Tag] =
    withReadLock clientsLock:
      let tagRefs = clientId2Tags.get(clientId)
      if not tagRefs.isNil:
        for t in tagRefs.val:
          result.add(t.tag[])

  iterator getClientIds*(tag: Tag): ClientId =
    withReadLock clientsLock:
      let clientIds = tag2ClientIds.get(tag)
      if not clientIds.isNil:
        for c in clientIds.val:
          yield c

  iterator getTags*(clientId: ClientId): Tag =
    withReadLock clientsLock:
      let tagRefs = clientId2Tags.get(clientId)
      if not tagRefs.isNil:
        for t in tagRefs.val:
          yield t.tag[]

  proc addTask*(clientId: ClientId, task: ClientTask) =
    withWriteLock clientsLock:
      let tasksPair = clientId2Tasks.get(clientId)
      if tasksPair.isNil:
        clientId2Tasks.set(clientId, @^[task])
      else:
        tasksPair.val.add(task)

  proc getTasks*(clientId: ClientId): Array[ClientTask] =
    withReadLock clientsLock:
      let tasksPair = clientId2Tasks.get(clientId)
      if not tasksPair.isNil:
        result = tasksPair.val

  proc setTasks*(clientId: ClientId, tasks: Array[ClientTask]) =
    withReadLock clientsLock:
      let tasksPair = clientId2Tasks.get(clientId)
      if tasksPair.isNil:
        clientId2Tasks.set(clientId, tasks)
      else:
        tasksPair.val = tasks

  proc purgeTasks*(clientId: ClientId, idx: int) =
    withReadLock clientsLock:
      let tasksPair = clientId2Tasks.get(clientId)
      if not tasksPair.isNil:
        tasksPair.val = tasksPair.val[idx + 1..^1]

  proc getAndPurgeTasks*(clientId: ClientId, cb: proc(task: ClientTask): bool): bool =
    result = true
    var tasksPair: HashTableData[ClientId, Array[ClientTask]]
    var tasks: Array[ClientTask]

    withReadLock clientsLock:
      tasksPair = clientId2Tasks.get(clientId)
      if tasksPair.isNil: return
      tasks = tasksPair.val

    var idx: int = -1
    for task in tasks:
      if not cb(task):
        result = false
        break
      inc(idx)

    if idx >= 0 and idx < tasksPair.val.len:
      withWriteLock clientsLock:
        for i in 0..idx:
          if tasksPair.val[i].cmd == ClientTaskCmd.Data:
            tasksPair.val[i].data.empty()
        if idx == tasks.high:
          clientId2Tasks.del(tasksPair)
        else:
          tasksPair.val = tasksPair.val[idx + 1..^1]

  proc delTasks*(clientId: ClientId) =
    withWriteLock clientsLock:
      let tasksPair = clientId2Tasks.get(clientId)
      if tasksPair.isNil: return
      for i, task in tasksPair.val:
        if task.cmd == ClientTaskCmd.Data:
          tasksPair.val[i].data.empty()
      clientId2Tasks.del(tasksPair)

  proc invokeSendEvent*(client: Client): bool =
    acquire(client.spinLock)
    if not client.appShift:
      inc(client.appId)
      client.appShift = true
    release(client.spinLock)
    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
    if retCtl != 0:
      return false
    return true

  proc send*(clientId: ClientId, data: string): SendResult {.discardable.} =
    let pair = pendingClients.get(clientId)
    if pair.isNil:
      return SendResult.None

    clientId.addTask(ClientTask(cmd: ClientTaskCmd.Data, data: data.toBytes.toArray))
    if pair.val.invokeSendEvent():
      result = SendResult.Pending
    else:
      clientId.delTasks()
      result = SendResult.Error

  proc addSendBuf*(client: Client, data: seq[byte] | string | Array[byte]) =
    let nextSize = client.sendCurSize + data.len
    client.sendBuf = reallocClientBuf(client.sendBuf, nextSize)
    copyMem(addr client.sendBuf[client.sendCurSize], unsafeAddr data[0], data.len)
    client.sendCurSize = nextSize

  proc addSendBuf*(client: Client, data: ptr UncheckedArray[byte], size: int) =
    let nextSize = client.sendCurSize + size
    client.sendBuf = reallocClientBuf(client.sendBuf, nextSize)
    copyMem(addr client.sendBuf[client.sendCurSize], addr data[0], size)
    client.sendCurSize = nextSize

  proc reserveRecvBuf(client: Client, size: int) =
    if client.recvBuf.isNil:
      client.recvBuf = cast[ptr UncheckedArray[byte]](allocShared0(sizeof(byte) * (size + workerRecvBufSize)))
      client.recvBufSize = size + workerRecvBufSize
    var left = client.recvBufSize - client.recvCurSize
    if size > left:
      var nextSize = client.recvCurSize + size + workerRecvBufSize
      if nextSize > cfg.recvBufExpandBreakSize:
        raise newException(ServerError, "client request too large")
      client.recvBuf = reallocClientBuf(client.recvBuf, nextSize)
      client.recvBufSize = nextSize

  proc addRecvBuf(client: Client, data: ptr UncheckedArray[byte], size: int) =
    client.reserveRecvBuf(size)
    copyMem(addr client.recvBuf[client.recvCurSize], addr data[0], size)
    client.recvCurSize = client.recvCurSize + size

  proc addRecvBuf(client: Client, data: ptr UncheckedArray[byte], size: int, reserveSize: int) =
    client.reserveRecvBuf(reserveSize)
    copyMem(addr client.recvBuf[client.recvCurSize], addr data[0], size)
    client.recvCurSize = client.recvCurSize + size

  proc sendNativeProc(client: Client, data: ptr UncheckedArray[byte], size: int): SendResult {.thread.} =
    var pos = 0
    var size = size
    while true:
      let sendRet = client.sock.send(cast[cstring](addr data[pos]), cast[cint](size), 0'i32)
      if sendRet == size:
        return SendResult.Success
      elif sendRet > 0:
        size = size - sendRet
        pos = pos + sendRet
        continue
      elif sendRet < 0:
        if errno == EAGAIN or errno == EWOULDBLOCK:
          acquire(client.lock)
          client.addSendBuf(cast[ptr UncheckedArray[byte]](addr data[pos]), size)
          release(client.lock)
          if client.invokeSendEvent():
            return SendResult.Pending
          else:
            return SendResult.Error
        elif errno == EINTR:
          continue
        return SendResult.Error
      else:
        return SendResult.None

  proc sendSslProc(client: Client, data: ptr UncheckedArray[byte], size: int): SendResult {.thread.} =
    when cfg.sslLib == BearSSL:
      acquire(client.lock)
      client.addSendBuf(cast[ptr UncheckedArray[byte]](addr data[0]), size)
      release(client.lock)
      return SendResult.Pending
    elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
      if client.sendCurSize > 0:
        acquire(client.lock)
        client.addSendBuf(cast[ptr UncheckedArray[byte]](addr data[0]), size)
        release(client.lock)
        return SendResult.Pending

      var pos = 0
      var size = size
      while true:
        let sendRet = client.ssl.SSL_write(cast[pointer](addr data[pos]), size.cint).int
        if sendRet == size:
          return SendResult.Success
        elif sendRet > 0:
          size = size - sendRet
          pos = pos + sendRet
          continue
        elif sendRet < 0:
          client.sslErr = SSL_get_error(client.ssl, sendRet.cint)
          debug "SSL_send err=", client.sslErr, " errno=", errno
          if client.sslErr == SSL_ERROR_WANT_WRITE or client.sslErr == SSL_ERROR_WANT_READ:
            acquire(client.lock)
            client.addSendBuf(cast[ptr UncheckedArray[byte]](addr data[pos]), size)
            release(client.lock)
            if client.invokeSendEvent():
              return SendResult.Pending
            else:
              return SendResult.Error
            return SendResult.Pending
          elif errno == EINTR:
            continue
          return SendResult.Error
        else:
          return SendResult.None

  proc send(client: Client, data: seq[byte] | string | Array[byte]): SendResult {.inline.} =
    return client.sendProc(client, cast[ptr UncheckedArray[byte]](unsafeAddr data[0]), data.len)

  proc sendFlush(client: Client): SendResult =
    if client.sendCurSize == 0:
      return SendResult.None

    var pos = 0
    var size = client.sendCurSize
    while true:
      var d = cast[cstring](addr client.sendBuf[pos])
      let sendRet = client.sock.send(d, size.cint, 0'i32)
      if sendRet > 0:
        debug "flush sendRet=", sendRet, " size=", size
        size = size - sendRet
        if size > 0:
          pos = pos + sendRet
          continue
        client.sendCurSize = 0
        deallocShared(cast[pointer](client.sendBuf))
        client.sendBuf = nil
        return SendResult.Success
      elif sendRet < 0:
        if errno == EAGAIN or errno == EWOULDBLOCK:
          copyMem(addr client.sendBuf[0], d, size)
          client.sendCurSize = size
          return SendResult.Pending
        if errno == EINTR:
          continue
        return SendResult.Error
      else:
        return SendResult.None

  when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
    proc sendSslFlush(client: Client): SendResult =
      if client.sendCurSize == 0:
        return SendResult.None

      var pos = 0
      var size = client.sendCurSize
      while true:
        var d = cast[cstring](addr client.sendBuf[pos])
        let sendRet = client.ssl.SSL_write(d, size.cint).int
        if sendRet > 0:
          debug "flush sendRet=", sendRet, " size=", size
          size = size - sendRet
          if size > 0:
            pos = pos + sendRet
            continue
          client.sendCurSize = 0
          deallocShared(cast[pointer](client.sendBuf))
          client.sendBuf = nil
          return SendResult.Success
        elif sendRet < 0:
          client.sslErr = SSL_get_error(client.ssl, sendRet.cint)
          if client.sslErr == SSL_ERROR_WANT_WRITE or client.sslErr == SSL_ERROR_WANT_READ:
            copyMem(addr client.sendBuf[0], d, size)
            client.sendCurSize = size
            return SendResult.Pending
          if errno == EINTR:
            continue
          return SendResult.Error
        else:
          return SendResult.None

  proc wsServerSend*(client: Client, data: seq[byte] | string | Array[byte],
                    opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult =
    var frame: seq[byte]
    var dataLen = data.len
    var finOp = 0x80.byte or opcode.byte
    if dataLen < 126:
      frame = BytesBE(finOp, dataLen.byte, data)
    elif dataLen <= 0xffff:
      frame = BytesBE(finOp, 126.byte, dataLen.uint16, data)
    else:
      frame = BytesBE(finOp, 127.byte, dataLen.uint64, data)
    result = client.send(frame)

  proc wsServerSend*(clientId: ClientId, data: seq[byte] | string | Array[byte],
                    opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult =
    var frame: seq[byte]
    var dataLen = data.len
    when data is Array:
      var data = data.toSeq
    else:
      var data = data.toBytes
    var finOp = 0x80.byte or opcode.byte
    if dataLen < 126:
      frame = BytesBE(finOp, dataLen.byte, data)
    elif dataLen <= 0xffff:
      frame = BytesBE(finOp, 126.byte, dataLen.uint16, data)
    else:
      frame = BytesBE(finOp, 127.byte, dataLen.uint64, data)
    result = clientId.send(frame.toString())

  template send(data: seq[byte] | string | Array[byte]): SendResult {.dirty.} = ctx.client.send(data)

  template wsSend(data: seq[byte] | string | Array[byte],
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.dirty.} =
    client.wsServerSend(data, opcode)

  template wsSend(clientId: ClientId, data: seq[byte] | string | Array[byte],
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.dirty.} =
    clientId.wsServerSend(data, opcode)

#[
when not declared(invokeSendMain):
  proc invokeSendMain(client: Client): SendResult =
    let clientId = client.clientId

    proc taskCallback(task: ClientTask): bool =
      let retSend = client.send(task.data.toSeq().toString())
      result = (retSend != SendResult.Pending)

    if clientId.getAndPurgeTasks(taskCallback):
      result = SendResult.None
    else:
      result = SendResult.Pending
]#
#[
proc quitServer(restart: bool = false) =
  debug "quit"
  restartFlag = restart
  active = false
  if serverSock != osInvalidSocket:
    if epfd >= 0:
      var ev: EpollEvent
      ev.events = EPOLLRDHUP
      var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, serverSock, addr ev)
      if retCtl != 0:
        errorQuit "error: quit epoll_ctl ret=", retCtl, " ", getErrnoStr()
    var retShutdown = serverSock.shutdown(SHUT_RD)
    if retShutdown != 0:
      errorQuit "error: quit shutdown ret=", retShutdown, " ", getErrnoStr()
    serverSock.close()
    serverSock = osInvalidSocket
  if httpSock != osInvalidSocket:
    var retShutdown = httpSock.shutdown(SHUT_RD)
    if retShutdown != 0:
      errorQuit "error: quit shutdown ret=", retShutdown, " ", getErrnoStr()
    httpSock.close()
    httpSock = osInvalidSocket

proc restart*() = quitServer(true)

proc abort() =
  debug "abort"
  abortFlag = true
  quitServer()
]#

var abort*: proc() {.thread.} = proc() {.thread.} = active = false

#  include stream

template serverInitFreeClient() {.dirty.} =
  import std/locks
  import queue2
  import ptlock
  import arraylib
  import logs

  var clients: ptr UncheckedArray[ClientObj] = nil
  var clientFreePool*: queue2.Queue[Client]

  proc initClient(clientMax: static int, ClientObj, Client: typedesc) =
    var p = cast[ptr UncheckedArray[ClientObj]](allocShared0(sizeof(ClientObj) * clientMax))
    for i in 0..<clientMax:
      p[i].sock = osInvalidSocket
      p[i].recvBuf = nil
      p[i].recvBufSize = 0
      p[i].recvCurSize = 0
      p[i].sendBuf = nil
      p[i].sendCurSize = 0
      p[i].keepAlive = true
      p[i].payloadSize = 0
      when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
        p[i].ssl = nil
      p[i].ip = 0
      p[i].invoke = false
      initLock(p[i].lock)
      initLock(p[i].spinLock)
      p[i].whackaMole = false
      p[i].ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
      p[i].ev.data = cast[EpollData](addr p[i])
      when declared(initExClient):
        initExClient(addr p[i])
    clients = p
    rwlockInit(clientsLock)
    pendingClients = newHashTable[ClientId, Client](clientMax * 3 div 2)
    tag2ClientIds = newHashTable[Tag, Array[ClientId]](clientMax * 10 * 3 div 2)
    clientId2Tags = newHashTable[ClientId, Array[TagRef]](clientMax * 3 div 2)
    clientId2Tasks = newHashTable[ClientId, Array[ClientTask]](clientMax * 3 div 2)

    try:
      clientFreePool.init(clientMax)
      for i in 0..<clientMax:
        clients[i].sock = osInvalidSocket
        clientFreePool.add(addr clients[i])
    except:
      let e = getCurrentException()
      errorRaise e.name, ": ", e.msg

  proc freeClient(clientMax: static int) =
    pendingClients.delete()
    rwlockDestroy(clientsLock)
    var p = clients
    clients = nil
    for i in 0..<clientMax:
      var client = addr p[i]
      if client.sock != osInvalidSocket:
        client.sock.close()
      if not client.recvBuf.isNil:
        deallocShared(cast[pointer](client.recvBuf))
      if not client.sendBuf.isNil:
        deallocShared(cast[pointer](client.sendBuf))
      when declared(freeExClient):
        freeExClient(client)
      deinitLock(client.spinLock)
      deinitLock(client.lock)
    deallocShared(p)

  proc close(client: Client, ssl: static bool = false) =
    acquire(client.spinLock)
    let sock = client.sock
    if sock != osInvalidSocket:
      client.sock = osInvalidSocket
      client.threadId = 0
      release(client.spinLock)
      when ssl:
        if not client.ssl.isNil:
          SSL_free(client.ssl)
          client.ssl = nil
          client.sslErr = SSL_ERROR_NONE
      sock.close()
      client.recvCurSize = 0
      client.recvBufSize = 0
      if not client.recvBuf.isNil:
        deallocShared(cast[pointer](client.recvBuf))
        client.recvBuf = nil
      if not client.sendBuf.isNil:
        deallocShared(cast[pointer](client.sendBuf))
        client.sendBuf = nil
      client.keepAlive = true
      client.payloadSize = 0
      client.appShift = false
      when cfg.sslLib == None:
        client.listenFlag = false
      acquire(client.lock)
      let clientId = client.clientId
      if clientId != INVALID_CLIENT_ID:
        clientId.delTags()
        clientId.delTasks()
        client.unmarkPending()
      release(client.lock)
      clientFreePool.addSafe(client)
    else:
      release(client.spinLock)

#[
proc setClient(fd: int): int =
  var usedCount = 0
  for i in clIdx..<CLIENT_MAX:
    var chk = -1
    if atomic_compare_exchange_n(addr clients[i].fd, addr chk, fd, false, 0, 0):
      clIdx = i + 1
      if clIdx >= CLIENT_MAX:
        clIdx = 0
      return i
    else:
      inc(usedCount)
      if usedCount > CLIENT_SEARCH_LIMIT:
        return -1
  for i in 0..<clIdx:
    var chk = -1
    if atomic_compare_exchange_n(addr clients[i].fd, addr chk, fd, false, 0, 0):
      clIdx = i + 1
      if clIdx >= CLIENT_MAX:
        clIdx = 0
      return i
    else:
      inc(usedCount)
      if usedCount > CLIENT_SEARCH_LIMIT:
        return -1
  return -1

proc sendInstant*(s: SocketHandle, data: string) =
  var sendRet: int
  while true:
    sendRet = s.send(data.cstring, data.len.cint, 0'i32)
    if sendRet < 0 and errno == EINTR:
      continue
    break

when ENABLE_SSL:
  proc sendInstant*(ssl: SSL, data: string) {.inline.} =
    var sendRet: int
    while true:
      sendRet = ssl.SSL_write(data.cstring, data.len.cint)
      if sendRet < 0 and errno == EINTR:
        continue
      break

proc sendInstant*(client: Client, data: string) {.inline.} =
  when ENABLE_SSL:
    if not client.ssl.isNil:
      client.ssl.sendInstant(data)
    else:
      client.fd.SocketHandle.sendInstant(data)
  else:
    client.fd.SocketHandle.sendInstant(data)



proc sendFlush(client: Client): SendResult =
  if client.sendCurSize == 0:
    return SendResult.None

  var sendRet: int
  var pos = 0
  var size = client.sendCurSize
  while true:
    var d = cast[cstring](addr client.sendBuf[pos])
    when ENABLE_SSL:
      if not client.ssl.isNil:
        sendRet = client.ssl.SSL_write(d, size.cint)
      else:
        sendRet = client.fd.SocketHandle.send(d, size.cint, 0'i32)
    else:
      sendRet = client.fd.SocketHandle.send(d, size.cint, 0'i32)
    if sendRet > 0:
      debug "flush sendRet=", sendRet, " size=", size
      size = size - sendRet
      if size > 0:
        pos = pos + sendRet
        continue
      client.sendCurSize = 0
      deallocShared(cast[pointer](client.sendBuf))
      client.sendBuf = nil
      return SendResult.Success
    elif sendRet < 0:
      when ENABLE_SSL:
        if not client.ssl.isNil:
          client.sslErr = SSL_get_error(client.ssl, sendRet.cint)
          debug "SSL_send err=", client.sslErr, " errno=", errno
          if client.sslErr == SSL_ERROR_WANT_WRITE or client.sslErr == SSL_ERROR_WANT_READ:
            copyMem(addr client.sendBuf[0], d, size)
            client.sendCurSize = size
            return SendResult.Pending
          else:
            if errno == EINTR:
              continue
          return SendResult.Error

      if errno == EAGAIN or errno == EWOULDBLOCK:
        copyMem(addr client.sendBuf[0], d, size)
        client.sendCurSize = size
        return SendResult.Pending
      if errno == EINTR:
        continue
      return SendResult.Error
    else:
      return SendResult.None

proc waitEventAgain(client: Client, evData: uint64, fd: int | SocketHandle, exEvents: uint32 = 0) =
  acquire(client.lock)
  defer:
    release(client.lock)
  var ev: EpollEvent
  if client.invoke:
    ev.events = EPOLLIN or EPOLLRDHUP or EPOLLOUT
    ev.data.u64 = client.idx.uint or 0x300000000'u64
    var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd.cint, addr ev)
    if ret < 0:
      error "error: epoll_ctl ret=", ret, " errno=", errno
      abort()
    else:
      client.invoke = false
  else:
    ev.events = EPOLLIN or EPOLLRDHUP or exEvents
    ev.data.u64 = evData
    var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd.cint, addr ev)
    if ret < 0:
      error "error: epoll_ctl ret=", ret, " errno=", errno
      abort()

when not declared(webMain):
  proc webMainDefault(client: Client, url: string, headers: Headers): SendResult =
    debug "web url=", url, " headers=", headers
    when DYNAMIC_FILES:
      var retFile = getDynamicFile(url)
    else:
      var retFile = getConstFile(url)
    if retFile.err == FileContentSuccess:
      var file = retFile.data
      if headers.getOrDefault("If-None-Match") == file.md5:
        result = client.send(Empty.addHeader(Status304))
      else:
        when not DYNAMIC_FILES or DYNAMIC_COMPRESS:
          let headersAcceptEncoding = headers.getOrDefault("Accept-Encoding")
          if file.content.len > 0 and headersAcceptEncoding.len > 0:
            var acceptEnc = headersAcceptEncoding.split(",")
            acceptEnc.apply(proc (x: string): string = x.strip)
            if acceptEnc.contains("br"):
              return client.send(file.brotli.addHeaderBrotli(file.md5, Status200, file.mime))
            elif acceptEnc.contains("deflate"):
              return client.send(file.deflate.addHeaderDeflate(file.md5, Status200, file.mime))
        return client.send(file.content.addHeader(file.md5, Status200, file.mime))
    else:
      when not DYNAMIC_FILES:
        var fileAcme = getAcmeChallenge(url)
        if fileAcme.content.len > 0:
          return client.send(fileAcme.content.addHeader(Status200, fileAcme.mime))
      return client.send(NotFound.addHeader(Status404))

when not declared(streamMain):
  proc streamMainDefault(client: Client, opcode: WebSocketOpCode,
                        data: ptr UncheckedArray[byte], size: int): SendResult =
    debug "ws opcode=", opcode, " size=", size
    case opcode
    of WebSocketOpcode.Binary, WebSocketOpcode.Text, WebSocketOpcode.Continue:
      result = client.wsServerSend(data.toString(size), WebSocketOpcode.Binary)
    of WebSocketOpcode.Ping:
      result = client.wsServerSend(data.toString(size), WebSocketOpcode.Pong)
    of WebSocketOpcode.Pong:
      debug "pong ", data.toString(size)
      result = SendResult.Success
    else: # WebSocketOpcode.Close
      result = SendResult.None

when not declared(invokeSendMain):
  proc invokeSendMainDefault(client: Client): SendResult =
    result = SendResult.None

var webMain: WebMainCallback = webMainDefault
var streamMain: StreamMainCallback = streamMainDefault

proc setWebMain*(webMainCallback: WebMainCallback) =
  webMain = webMainCallback

proc setStreamMain*(streamMainCallback: StreamMainCallback) =
  streamMain = streamMainCallback

proc workerMain(client: Client, buf: ptr UncheckedArray[byte], size: int, appId: int): SendResult =
  var i = 0
  var cur = 0
  var first = true
  var cmd = ""
  var url = ""
  var keepAlive = false
  var retMain = SendResult.None
  var headers = initTable[string, string]()

  while i < size - 3:
    if equalMem(addr buf[i], "\c\L".cstring, 2):
      var reqdata = (cast[ptr UncheckedArray[byte]](addr buf[cur])).toString(i - cur)
      if first:
        first = false
        var cmdparams = reqdata.split(" ").filter(proc (x: string): bool = x.len > 0)
        if cmdparams.len >= 2:
          cmd = cmdparams[0]
          if cmd != "GET":
            error "invalid request cmd=", cmd.toBytes
            return SendResult.Invalid
          var urlpath = cgi.decodeUrl(cmdparams[1])
          if urlpath.split("/").contains(".."):
            error "invalid request path: ", urlpath
            return SendResult.Invalid
          url = normalizedPath(urlpath)
          if urlpath.endsWith("/") and not url.endsWith("/"):
            url = url & "/"
          if cmdparams.len >= 3 and cmdparams[2] == "HTTP/1.1":
            keepAlive = true
      else:
        var pos = reqdata.find(":")
        if pos > 0:
          headers[reqdata[0..pos-1]] = reqdata[pos+1..^1].strip
        else:
          error "invalid request reqdata=", reqdata
          return SendResult.Invalid

      inc(i, 2)
      if equalMem(addr buf[i], "\c\L".cstring, 2):
        let headersHost = headers.getOrDefault("Host")
        if headersHost.len > 0:
          if appId == 1:
            if headersHost != HTTP_HOST_NAME:
              error "invalid request host mismatch ", headersHost, " ", HTTP_HOST_NAME
              return SendResult.Invalid
            return client.send(redirect301(REDIRECT_URL & url))
          else:
            if headersHost != HTTPS_HOST_NAME:
              error "invalid request host mismatch ", headersHost, " ", HTTPS_HOST_NAME
              return SendResult.Invalid
        else:
          error "invalid request no host headers=", headers
          return SendResult.Invalid

        if url == WEBSOCKET_ENTRY_POINT:
          let key = headers.getOrDefault("Sec-WebSocket-Key")
          if headers.hasKey("Sec-WebSocket-Version") and key.len > 0 and
            headers.getOrDefault("Sec-WebSocket-Protocol") == WEBSOCKET_PROTOCOL:
            var sh = secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
            var acceptKey = base64.encode(sh.Sha1Digest)
            var res = "HTTP/1.1 " & $Status101 & "\c\L" &
                      "Upgrade: websocket\c\L" &
                      "Connection: Upgrade\c\L" &
                      "Sec-WebSocket-Accept: " & acceptKey & "\c\L" &
                      "Sec-WebSocket-Protocol: " & WEBSOCKET_PROTOCOL & "\c\L" &
                      "Sec-WebSocket-Version: 13\c\L\c\L"
            client.wsUpgrade = true
            debug "ws upgrade url=", url, " headers=", headers
            when declared(streamConnect):
              var sendRet = client.send(res)
              if sendRet == SendResult.Success or sendRet == SendResult.Pending:
                var (sendFlag, sendResult) = client.streamConnect()
                if sendFlag and sendResult != SendResult.Success:
                  sendRet = sendResult
              return sendRet
            else:
              return client.send(res)
          else:
            error "error: websocket protocol headers=", headers
            raise newException(ServerError, "websocket protocol error")

        retMain = client.webMain(url, headers)
        if not keepAlive or headers.getOrDefault("Connection") == "close":
          client.keepAlive = false
          return retMain

        inc(i, 2)
        if i >= size:
          return retMain

        first = true
        cmd = ""
        url = ""
        keepAlive = false
        headers = initTable[string, string]()

      cur = i
    inc(i)

  return retMain

proc worker(arg: ThreadArg) {.thread.} =
  when declared(initWorker):
    initWorker()
  var recvBuf = newSeq[byte](arg.workerParams.bufLen)

  proc reserveRecvBuf(client: Client, size: int) =
    if client.recvBuf.isNil:
      client.recvBuf = cast[ptr UncheckedArray[byte]](allocShared0(sizeof(byte) * (size + arg.workerParams.bufLen)))
      client.recvBufSize = size + arg.workerParams.bufLen
    var left = client.recvBufSize - client.recvCurSize
    if size > left:
      var nextSize = client.recvCurSize + size + arg.workerParams.bufLen
      if nextSize > RECVBUF_EXPAND_BREAK_SIZE:
        raise newException(ServerError, "client request too large")
      client.recvBuf = reallocClientBuf(client.recvBuf, nextSize)
      client.recvBufSize = nextSize

  proc addRecvBuf(client: Client, data: ptr UncheckedArray[byte], size: int) =
    client.reserveRecvBuf(size)
    copyMem(addr client.recvBuf[client.recvCurSize], addr data[0], size)
    client.recvCurSize = client.recvCurSize + size

  when DYNAMIC_FILES:
    initDynamicFile()

  while true:
    block channelBlock:
      var channelData = workerQueue.recv()
      if not active:
        when declared(freeWorker):
          freeWorker()
        return
      var appId = channelData.appId
      var idx = channelData.idx
      var events = channelData.events
      var evData = channelData.evData
      debug "appId=", appId, " idx=", idx, " ev=", events, " tid=", arg.workerParams.threadId

      var client = addr clients[idx]
      var clientFd = client.fd
      var clientSock = clientFd.SocketHandle
      client.whackaMole = false

      try:
        when ENABLE_SSL:
          ERR_clear_error()

          if appId == 4:
            while true:
              let retSslAccept = SSL_Accept(client.ssl)
              if retSslAccept < 0:
                var ev: EpollEvent
                client.sslErr = SSL_get_error(client.ssl, retSslAccept)
                debug "SSL_accept err=", client.sslErr, " errno=", errno
                if client.sslErr == SSL_ERROR_WANT_READ:
                  ev.events = EPOLLIN or EPOLLRDHUP
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  ev.events = EPOLLIN or EPOLLRDHUP or EPOLLOUT
                else:
                  if errno == EINTR:
                    continue
                  client.close()
                  break channelBlock

                ev.data.u64 = client.idx.uint or 0x400000000'u64
                var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, clientFd.cint, addr ev)
                if ret < 0:
                  error "error: epoll_ctl ret=", ret, " errno=", errno
                  abort()
              elif retSslAccept == 0:
                client.close()
              else:
                client.waitEventAgain(client.idx.uint, clientFd)
              break channelBlock

        if client.sendBuf != nil:
          if (events and EPOLLOUT) > 0:
            var retFlush = client.sendFlush()
            if retFlush == SendResult.Pending:
              when ENABLE_SSL:
                if client.sslErr == SSL_ERROR_WANT_READ:
                  client.waitEventAgain(evData, clientFd)
                else:
                  client.waitEventAgain(evData, clientFd, EPOLLOUT)
              else:
                client.waitEventAgain(evData, clientFd, EPOLLOUT)
              break channelBlock
            if retFlush != SendResult.Success or not client.keepAlive:
              client.close()
              break channelBlock
          if (events and (EPOLLIN or EPOLLRDHUP)) == 0 and appId != 3:
            client.waitEventAgain(evData, clientFd)
            break channelBlock

        if appId == 3:
          when declared(invokeSendMain):
            var retInvoke = client.invokeSendMain()
          else:
            var retInvoke = client.invokeSendMainDefault()

          if retInvoke == SendResult.Pending:
            when ENABLE_SSL:
              if client.sslErr == SSL_ERROR_WANT_READ:
                client.waitEventAgain(evData, clientFd)
              else:
                client.waitEventAgain(evData, clientFd, EPOLLOUT)
            else:
              client.waitEventAgain(evData, clientFd, EPOLLOUT)
            break channelBlock
          evData = evData and 0xffffffff'u64 # drop AppId
          if (events and (EPOLLIN or EPOLLRDHUP)) == 0:
            client.waitEventAgain(evData, clientFd)
            break channelBlock

        if appId == 2:
          if client.wsUpgrade:
            error "error: ws too many ", inet_ntoa(InAddr(s_addr: client.ip))
            client.close()
            break channelBlock
          else:
            error "error: too many ", inet_ntoa(InAddr(s_addr: client.ip))
            clientSock.sendInstant(TooMany.addHeader(Status429))
            clientSock.close()
            break channelBlock

        template retWorkerHandler(retWorker: SendResult) {.dirty.} =
          case retWorker
          of SendResult.Success:
            if not client.keepAlive:
              client.close()
              break channelBlock
          of SendResult.Pending:
            when ENABLE_SSL:
              if client.sslErr == SSL_ERROR_WANT_READ:
                client.waitEventAgain(evData, clientFd)
              else:
                client.waitEventAgain(evData, clientFd, EPOLLOUT)
            else:
              client.waitEventAgain(evData, clientFd, EPOLLOUT)
            break channelBlock
          of SendResult.Invalid:
            client.sendInstant(BadRequest.addHeader(Status400))
            client.close()
            break channelBlock
          of SendResult.None, SendResult.Error:
            client.close()
            break channelBlock

        template retStreamHandler(retStream: SendResult) {.dirty.} =
          case retStream
          of SendResult.Success:
            discard
          of SendResult.Pending:
            when ENABLE_SSL:
              if client.sslErr != SSL_ERROR_WANT_READ:
                exEvents = EPOLLOUT
            else:
              exEvents = EPOLLOUT
          of SendResult.None, SendResult.Error, SendResult.Invalid:
            client.close()
            break channelBlock

        var recvlen: int
        if client.recvBufSize == 0:
          while true:
            when ENABLE_SSL:
              if not client.ssl.isNil:
                recvlen = client.ssl.SSL_read(addr recvBuf[0], recvBuf.len.cint)
              else:
                recvlen = clientSock.recv(addr recvBuf[0], recvBuf.len.cint, 0.cint)

            else:
              recvlen = clientSock.recv(addr recvBuf[0], recvBuf.len.cint, 0.cint)
            if recvlen > 0:
              if client.wsUpgrade:
                var exEvents = 0'u32
                var (find, fin, opcode, payload, payloadSize,
                    next, size) = getFrame(cast[ptr UncheckedArray[byte]](addr recvBuf[0]), recvlen)
                while find:
                  if fin:
                    var retStream = client.streamMain(opcode.toWebSocketOpCode, payload, payloadSize)
                    retStreamHandler(retStream)
                  else:
                    if not payload.isNil and payloadSize > 0:
                      client.addRecvBuf(payload, payloadSize)
                      client.payloadSize = payloadSize
                    break
                  (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

                if not next.isNil and size > 0:
                  client.addRecvBuf(next, size)
                  if recvlen == recvBuf.len:
                    break

                client.waitEventAgain(evData, clientFd, exEvents)
                break channelBlock

              elif recvlen >= 4 and recvBuf[recvlen - 4].toUint32 == CLCL:
                var retWorker = workerMain(client, cast[ptr UncheckedArray[byte]](addr recvBuf[0]), recvlen, appId)
                retWorkerHandler(retWorker)
              elif recvlen >= 4 and recvBuf[0..3].toString != "GET ":
                  error "invalid request cmd=", recvBuf[0..<recvlen]
                  clientSock.sendInstant(Empty.addHeader(Status405))
                  client.close()
                  break channelBlock
              else:
                client.addRecvBuf(cast[ptr UncheckedArray[byte]](addr recvBuf[0]), recvlen)
                if recvlen == recvBuf.len:
                  break
              client.waitEventAgain(evData, clientFd)
              break channelBlock
            elif recvlen == 0:
              client.close()
              break channelBlock
            else:
              when ENABLE_SSL:
                if not client.ssl.isNil:
                  client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                  debug "SSL_read err=", client.sslErr, " errno=", errno
                  if client.sslErr == SSL_ERROR_WANT_READ:
                    client.waitEventAgain(evData, clientFd)
                    break channelBlock
                  elif client.sslErr == SSL_ERROR_WANT_WRITE:
                    client.waitEventAgain(evData, clientFd, EPOLLOUT)
                    break channelBlock
                  else:
                    if errno == EINTR:
                      continue
                  client.close()
                  break channelBlock

              if errno == EAGAIN or errno == EWOULDBLOCK:
                client.waitEventAgain(evData, clientFd)
                break channelBlock
              if errno == EINTR:
                continue
              client.close()
              break channelBlock

        while true:
          client.reserveRecvBuf(arg.workerParams.bufLen)
          when ENABLE_SSL:
            if not client.ssl.isNil:
              recvlen = client.ssl.SSL_read(addr client.recvBuf[client.recvCurSize], arg.workerParams.bufLen.cint)
            else:
              recvlen = clientSock.recv(addr client.recvBuf[client.recvCurSize], arg.workerParams.bufLen.cint, 0.cint)
          else:
            recvlen = clientSock.recv(addr client.recvBuf[client.recvCurSize], arg.workerParams.bufLen.cint, 0.cint)
          if recvlen > 0:
            client.recvCurSize = client.recvCurSize + recvlen
            if client.wsUpgrade:
              var exEvents = 0'u32
              var p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
              var (find, fin, opcode, payload, payloadSize,
                  next, size) = getFrame(p, client.recvCurSize - client.payloadSize)
              while find:
                if not payload.isNil and payloadSize > 0:
                  copyMem(p, payload, payloadSize)
                  client.payloadSize = client.payloadSize + payloadSize
                  p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
                if fin:
                  var retStream = client.streamMain(opcode.toWebSocketOpCode,
                                                    cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]),
                                                    client.payloadSize)
                  retStreamHandler(retStream)
                  client.payloadSize = 0
                  client.recvCurSize = 0
                (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

              if not next.isNil and size > 0:
                copyMem(p, next, size)
                client.recvCurSize = client.payloadSize + size
                if recvlen == arg.workerParams.bufLen:
                  continue
              else:
                client.recvCurSize = client.payloadSize

              client.waitEventAgain(evData, clientFd, exEvents)
              break channelBlock

            elif client.recvCurSize >= 4 and client.recvBuf[client.recvCurSize - 4].toUint32 == CLCL:
              var retWorker = workerMain(client, cast[ptr UncheckedArray[byte]](client.recvBuf), client.recvCurSize, appId)
              client.recvCurSize = 0
              client.recvBufSize = 0
              deallocShared(cast[pointer](client.recvBuf))
              client.recvBuf = nil
              retWorkerHandler(retWorker)
            elif recvlen == arg.workerParams.bufLen:
              continue
            client.waitEventAgain(evData, clientFd)
            break channelBlock
          elif recvlen == 0:
            client.close()
            break channelBlock
          else:
            when ENABLE_SSL:
              if not client.ssl.isNil:
                client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                debug "SSL_read err=", client.sslErr, " errno=", errno
                if client.sslErr == SSL_ERROR_WANT_READ:
                  client.waitEventAgain(evData, clientFd)
                  break channelBlock
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  client.waitEventAgain(evData, clientFd, EPOLLOUT)
                  break channelBlock
                else:
                  if errno == EINTR:
                    continue
                client.close()
                break channelBlock

            if errno == EAGAIN or errno == EWOULDBLOCK:
              client.waitEventAgain(evData, clientFd)
              break channelBlock
            if errno == EINTR:
              continue
            client.close()
            break channelBlock

      except ServerNeedRestartError:
        let e = getCurrentException()
        error e.name, ": ", e.msg
        restart()

      except:
        client.close()
        let e = getCurrentException()
        error e.name, ": ", e.msg

proc dispatcher(arg: ThreadArg) {.thread.} =
  var reqStats = newCheckReqs(REQ_LIMIT_DISPATCH_PERIOD)

  while true:
    var nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                        EPOLL_EVENTS_SIZE.cint, 3000.cint)
    if not active:
      break
    if nfd > 0:
      for i in 0..<nfd:
        var evData = events[i].data.u64
        var appId = (evData shr 32).int
        var idx = (evData and 0xffffffff'u64).int
        var clientFd = clients[idx].fd
        var ret = epoll_ctl(epfd, EPOLL_CTL_DEL, clientFd.cint, nil)
        if ret < 0:
          error "error: epoll_ctl ret=", ret, " errno=", errno
          abort()

        if appId != 3:
          var reqCount = reqStats.checkReq(clients[idx].ip)
          if reqCount > REQ_LIMIT_DISPATCH_MAX:
            appId = 2

        workerQueue.send((appId, idx, events[i].events, evData))
        workerChannelWaitingCount = workerQueue.count
    elif nfd < 0:
        if errno == EINTR:
          continue
        error "error: epoll_wait ret=", nfd, " errno=", errno
        abort()

when ENABLE_SSL:
  import macros except error
  export tables

  type
    SiteCtx = object
      ctx: SSL_CTX
      updated: bool
      watchdog: cint

  var siteCtxs: array[CERT_SITES.len, SiteCtx]

  when SSL_AUTO_RELOAD:
    import std/inotify
    import ptlock

    type
      SslFileHash* = object
        cert: array[32, byte]
        priv: array[32, byte]
        chain: array[32, byte]

    var sslFileChanged = false
    var sslFileUpdateLock: RWLock
    var sslFileHash: ptr UncheckedArray[SslFileHash]
    var inoty: FileHandle
    var inotyWatchFlag: bool

    proc setSslFilesWatch() =
      if inoty == -1:
        inoty = inotify_init()
        if inoty == -1:
          error "error: inotify_init err=", errno
          return
      for i, site in CERT_SITES:
        if siteCtxs[i].watchdog == -1:
          let sitePath = CERT_PATH / site
          siteCtxs[i].watchdog = inotify_add_watch(inoty, cstring(sitePath), IN_CLOSE_WRITE)
          if siteCtxs[i].watchdog == -1:
            error "error: inotify_add_watch err=", errno, " ", sitePath
          else:
            inotyWatchFlag = true

    proc setSslFileHash(init: bool = false) =
      if sslFileHash.isNil:
        if init:
          rwlockInit(sslFileUpdateLock)
          sslFileHash = cast[ptr UncheckedArray[SslFileHash]](allocShared0(sizeof(SslFileHash) * CERT_SITES.len))
          inoty = -1
          for i in 0..<CERT_SITES.len:
            siteCtxs[i].watchdog = -1
          setSslFilesWatch()
        else:
          return
      else:
        setSslFilesWatch()

      var changeFlag = false
      for i, site in CERT_SITES:
        try:
          let certs = certsTable[site]
          let cert = sha256.digest(readFile(certs.cert)).data
          let priv = sha256.digest(readFile(certs.privkey)).data
          let chain = sha256.digest(readFile(certs.fullchain)).data
          if init == false:
            if sslFileHash[i].cert != cert or
              sslFileHash[i].priv != priv or
              sslFileHash[i].chain != chain:
              changeFlag = true
              debug "SSL file changed"
          copyMem(addr sslFileHash[i].cert[0], unsafeAddr cert[0], 32)
          copyMem(addr sslFileHash[i].priv[0], unsafeAddr priv[0], 32)
          copyMem(addr sslFileHash[i].chain[0], unsafeAddr chain[0], 32)
        except:
          let e = getCurrentException()
          error "setSslFileHash ", e.name, ": ", e.msg
      if changeFlag:
        withWriteLock sslFileUpdateLock:
          sslFileChanged = true

    proc initSslFileHash() {.inline.} = setSslFileHash(true)

    proc freeSslFileHash() =
      if inoty != -1:
        for i in 0..<CERT_SITES.len:
          if siteCtxs[i].watchdog != -1:
            discard inoty.inotify_rm_watch(siteCtxs[i].watchdog)
        discard inoty.close()
      if not sslFileHash.isNil:
        var p = sslFileHash
        sslFileHash = nil
        deallocShared(p)
      rwlockDestroy(sslFileUpdateLock)

    proc checkSslFileHash() {.inline.} = setSslFileHash()

  proc serverNameCallback(ssl: SSL; out_alert: ptr cint; arg: pointer): cint {.cdecl.} =
    try:
      let sitename = $SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
      debug "sitename=", sitename
      let certs = certsTable[sitename]
      let ctx = siteCtxs[certs.idx].ctx
      if SSL_set_SSL_CTX(ssl, ctx).isNil:
        error "error: SSL_set_SSL_CTX site=", sitename
        return SSL_TLSEXT_ERR_NOACK
      return SSL_TLSEXT_ERR_OK
    except:
      return SSL_TLSEXT_ERR_OK

proc acceptClient(arg: ThreadArg) {.thread.} =
  when ENABLE_SSL:
    when SSL_AUTO_RELOAD:
      initSslFileHash()
    var ctx = newSslCtx(selfSignedCertFallback = true)
    for i, site in CERT_SITES:
      siteCtxs[i].ctx = newSslCtx(site, selfSignedCertFallback = true)
      siteCtxs[i].updated = false
    SSL_CTX_set_tlsext_servername_callback(ctx, serverNameCallback)

  var reqStats = newCheckReqs(REQ_LIMIT_HTTPS_ACCEPT_PERIOD)

  while true:
    var sockAddress: Sockaddr_in
    var addrLen = sizeof(sockAddress).SockLen
    var clientSock = accept(serverSock, cast[ptr SockAddr](addr sockAddress), addr addrLen)
    if not active: break
    var clientFd = clientSock.int
    if clientFd < 0:
      if errno == EINTR:
        continue
      error "error: accept errno=", errno
      abort()

    when ENABLE_KEEPALIVE:
      clientSock.setSockOptInt(SOL_SOCKET, SO_KEEPALIVE, 1)
    when ENABLE_TCP_NODELAY:
      clientSock.setSockOptInt(Protocol.IPPROTO_TCP.int, TCP_NODELAY, 1)
    var ip = sockAddress.sin_addr.s_addr
    var address = inet_ntoa(sockAddress.sin_addr)

    debug "client ip=", $address, " fd=", clientFd

    when ENABLE_SSL:
      when SSL_AUTO_RELOAD:
        withWriteLock sslFileUpdateLock:
          if sslFileChanged:
            sslFileChanged = false
            var oldCtx = ctx
            ctx = newSslCtx(selfSignedCertFallback = true)
            oldCtx.SSL_CTX_free()
            for i, site in CERT_SITES:
              if siteCtxs[i].updated:
                var oldCtx = siteCtxs[i].ctx
                siteCtxs[i].ctx = newSslCtx(site, selfSignedCertFallback = true)
                siteCtxs[i].updated = false
                oldCtx.SSL_CTX_free()
            SSL_CTX_set_tlsext_servername_callback(ctx, serverNameCallback)
            debug "SSL ctx updated"

      var ssl = SSL_new(ctx)
      if SSL_set_fd(ssl, clientFd.cint) != 1:
        error "error: SSL_set_fd"
        SSL_free(ssl)
        clientSock.close()
        continue

    template acceptInstant(body: untyped) =
      clientSock.setBlocking(false)
      var retryCount: int
      while true:
        let retSslAccept = SSL_accept(ssl)
        if retSslAccept >= 0:
          body
          break
        if retryCount >= 10:
          debug "accept giveup"
          break
        sleep(10)
        inc(retryCount)
        debug "accept retry count=", retryCount, " ", SSL_get_error(ssl, retSslAccept)

    template busyErrorContinue() =
      when ENABLE_SSL:
        acceptInstant:
          ssl.sendInstant(BusyBody.addHeader(Status503))
        SSL_free(ssl)
      else:
        clientSock.sendInstant(BusyBody.addHeader(Status503))
      clientSock.close()
      continue

    if workerChannelWaitingCount > WORKER_QUEUE_LIMIT:
      error "error: worker busy"
      busyErrorContinue()

    var reqCount = reqStats.checkReq(ip)
    if reqCount > REQ_LIMIT_HTTPS_ACCEPT_MAX:
      error "error: too many ", $address
      when ENABLE_SSL:
        acceptInstant:
          ssl.sendInstant(TooMany.addHeader(Status429))
        SSL_free(ssl)
      else:
        clientSock.sendInstant(TooMany.addHeader(Status429))
      clientSock.close()
      continue

    var idx = setClient(clientFd)
    if idx < 0:
      error "error: server full"
      busyErrorContinue()

    when ENABLE_SSL:
      clients[idx].ssl = ssl
    clients[idx].ip = ip

    clientSock.setBlocking(false)

    var ev: EpollEvent
    when ENABLE_SSL:
      ev.events = EPOLLIN or EPOLLRDHUP or EPOLLOUT
      ev.data.u64 = idx.uint or 0x400000000'u64
    else:
      ev.events = EPOLLIN or EPOLLRDHUP
      ev.data.u64 = idx.uint
    var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, clientFd.cint, addr ev)
    if ret < 0:
      error "error: epoll_ctl ret=", ret, " errno=", errno
      abort()

proc http(arg: ThreadArg) {.thread.} =
  var reqStats = newCheckReqs(REQ_LIMIT_HTTP_ACCEPT_PERIOD)

  while active:
    var sockAddress: Sockaddr_in
    var addrLen = sizeof(sockAddress).SockLen
    var clientSock = accept(httpSock, cast[ptr SockAddr](addr sockAddress), addr addrLen)
    var clientFd = clientSock.int
    if clientFd < 0:
      if errno == EINTR:
        continue
      error "error: accept errno=", errno
      abort()

    var ip = sockAddress.sin_addr.s_addr
    var address = inet_ntoa(sockAddress.sin_addr)

    debug "client ip=", $address, " fd=", clientFd

    template busyErrorContinue() =
      clientSock.sendInstant(BusyBody.addHeader(Status503))
      clientSock.close()
      continue

    if workerChannelWaitingCount > WORKER_QUEUE_LIMIT:
      error "error: worker busy"
      busyErrorContinue()

    var reqCount = reqStats.checkReq(ip)
    if reqCount > REQ_LIMIT_HTTP_ACCEPT_MAX:
      error "error: too many ", $address
      clientSock.sendInstant(TooMany.addHeader(Status429))
      clientSock.close()
      continue

    var idx = setClient(clientFd)
    if idx < 0:
      error "error: server full"
      busyErrorContinue()

    clients[idx].ip = ip

    clientSock.setBlocking(false)

    var ev: EpollEvent
    ev.events = EPOLLIN or EPOLLRDHUP
    ev.data.u64 = idx.uint or 0x100000000'u64
    var ret = epoll_ctl(epfd, EPOLL_CTL_ADD, clientFd.cint, addr ev)
    if ret < 0:
      error "error: epoll_ctl ret=", ret, " errno=", errno
      abort()

proc serverMonitor(arg: ThreadArg) {.thread.} =
  var prevTime = getTime()
  var sec = 0
  while active:
    if sec >= 60:
      sec = 0
      when ENABLE_SSL:
        when SSL_AUTO_RELOAD:
          if not sslFileChanged:
            var curTime = getTime()
            let dur = curTime - prevTime
            if dur >= initDuration(hours = 1):
              checkSslFileHash()
              prevTime = curTime

      for i in 0..<CLIENT_MAX:
        if clients[i].fd != osInvalidSocket.int and not clients[i].wsUpgrade:
          if clients[i].whackaMole:
            debug "Whack-A-Mole shutdown i=", i
            let retShutdown = clients[i].fd.SocketHandle.shutdown(SHUT_RD)
            if retShutdown != 0:
              error "error: Whack-A-Mole shutdown ret=", retShutdown, " ", getErrnoStr()
          else:
            debug "Whack-A-Mole set i=", i
            clients[i].whackaMole = true

    sleep(1000)
    inc(sec)

  when ENABLE_SSL:
    when SSL_AUTO_RELOAD:
      freeSslFileHash()

when ENABLE_SSL and SSL_AUTO_RELOAD:
  proc fileWatcher(arg: ThreadArg) {.thread.} =
    var evs = newSeq[byte](sizeof(InotifyEvent) * 512)
    while active:
      if not inotyWatchFlag:
        sleep(1000)
        continue
      let n = read(inoty, evs[0].addr, evs.len)
      if n <= 0: break
      var updated = false
      withWriteLock sslFileUpdateLock:
        for e in inotify_events(evs[0].addr, n):
          if e[].len > 0:
            debug "file updated name=", $cast[cstring](addr e[].name)
            for i in 0..<CERT_SITES.len:
              if siteCtxs[i].watchdog == e[].wd:
                siteCtxs[i].updated = true
                if $cast[cstring](addr e[].name) == CHAIN_FILE:
                  # certbot writes fullchain file last, your script must also copy fullchain file last
                  updated = true
                break
        if updated:
          sleep(3000)
          sslFileChanged = true
]#

proc createServer(bindAddress: string, port: uint16, reusePort: bool = false): SocketHandle =
  let sock = createNativeSocket()
  let aiList = getAddrInfo(bindAddress, port.Port, Domain.AF_INET)
  sock.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1)
  if reusePort:
    sock.setSockOptInt(SOL_SOCKET, SO_REUSEPORT, 1)
  let retBind = sock.bindAddr(aiList.ai_addr, aiList.ai_addrlen.SockLen)
  if retBind < 0:
    errorRaise "error: bind ret=", retBind, " ", getErrnoStr()
  freeaddrinfo(aiList)

  let retListen = sock.listen()
  if retListen < 0:
    errorRaise "error: listen ret=", retListen, " ", getErrnoStr()
  result = sock

proc threadWrapper(wrapperArg: WrapperThreadArg) {.thread.} =
  try:
    wrapperArg.threadFunc(wrapperArg.arg)
  except:
    let e = getCurrentException()
    echo e.name, ": ", e.msg
    abort()

#[
proc main(arg: ThreadArg) {.thread.} =
  while true:
    serverSock = createServer("0.0.0.0", HTTPS_PORT)
    httpSock = createServer("0.0.0.0", HTTP_PORT)

    var tcp_rmem = serverSock.getSockOptInt(SOL_SOCKET, SO_RCVBUF)
    debug "RECVBUF=", tcp_rmem

    epfd = epoll_create1(O_CLOEXEC)
    if epfd < 0:
      errorQuit "error: epfd=", epfd, " errno=", errno

    when declared(initStream):
      initStream()

    initClient()

    startTimeStampUpdater()
    for i in 0..<WORKER_THREAD_NUM:
      createThread(workerThreads[i], threadWrapper,
                  (worker, ThreadArg(type: ThreadArgType.WorkerParams, workerParams: (i, tcp_rmem))))

    createThread(dispatcherThread, threadWrapper, (dispatcher, ThreadArg(type: ThreadArgType.Void)))
    createThread(acceptThread, threadWrapper, (acceptClient, ThreadArg(type: ThreadArgType.Void)))
    createThread(httpThread, threadWrapper, (http, ThreadArg(type: ThreadArgType.Void)))
    createThread(monitorThread, threadWrapper, (serverMonitor, ThreadArg(type: ThreadArgType.Void)))
    when ENABLE_SSL and SSL_AUTO_RELOAD:
      createThread(fileWatcherThread, threadWrapper, (fileWatcher, ThreadArg(type: ThreadArgType.Void)))
      joinThreads(fileWatcherThread, monitorThread, httpThread, acceptThread, dispatcherThread)
    else:
      joinThreads(monitorThread, httpThread, acceptThread, dispatcherThread)

    for i in 0..<WORKER_THREAD_NUM:
      workerQueue.send((0, 0, 0'u32, 0'u64))
    joinThreads(workerThreads)

    var retEpfdClose = epfd.close()
    if retEpfdClose != 0:
      errorQuit "error: close epfd=", epfd, " ret=", retEpfdClose, " ", getErrnoStr()

    freeClient()

    when declared(freeStream):
      freeStream()

    joinThread(contents.timeStampThread)

    if restartFlag:
      active = true
    else:
      break

proc start*() = threadWrapper((main, ThreadArg(type: ThreadArgType.Void)))
]#

var releaseOnQuitSocks: Array[SocketHandle]
var releaseOnQuitEpfds: Array[cint]

proc addReleaseOnQuit(sock: SocketHandle) = releaseOnQuitSocks.add(sock)

proc addReleaseOnQuit(epfd: cint) = releaseOnQuitEpfds.add(epfd)

#[
proc stop*() {.inline.} =
  if not abortFlag:
    quitServer()
]#

var initServerFlag {.compileTime.} = false
var curSrvId {.compileTime.} = 0
var curAppId {.compileTime.} = 0
var curResId {.compileTime.} = 0
var serverWorkerInitStmt {.compileTime.} = newStmtList()
var serverWorkerMainStmt {.compileTime.} =
  nnkStmtList.newTree(
    nnkCaseStmt.newTree(
      newIdentNode(""),
      nnkElse.newTree(
        nnkStmtList.newTree(
          nnkDiscardStmt.newTree(
            newEmptyNode()
          )
        )
      )
    )
  )
var serverHandlerList* {.compileTime.} = @[("appDummy", ident("false"), newStmtList())]
var freePoolServerUsedCount* {.compileTime.} = 0
var sockTmp = createNativeSocket()
var workerRecvBufSize*: int = sockTmp.getSockOptInt(SOL_SOCKET, SO_RCVBUF)
sockTmp.close()
var serverWorkerNum*: int
var highGear* = false

macro initServer*(): untyped =
  if not initServerFlag:
    initServerFlag = true
    quote do:
      serverInitFreeClient()
      initClient(cfg.clientMax, ClientObj, Client)
  else:
    quote do:
      discard

macro getAppId*(): int =
  inc(curAppId)
  newLit(curAppId)

macro addServerMacro*(bindAddress: string, port: uint16, ssl: bool, sslLib: SslLib, body: untyped = newEmptyNode()): untyped =
  inc(curSrvId)
  var srvId = curSrvId
  inc(curAppId)
  var appId = curAppId
  serverHandlerList.add(("appListen", ssl, newStmtList()))
  inc(curAppId) # reserved
  var appRoutes = curAppId
  serverHandlerList.add(("appRoutes", ssl, newStmtList()))
  if eqIdent("true", ssl) and (eqIdent("OpenSSL", sslLib) or eqIdent("LibreSSL", sslLib) or eqIdent("BoringSSL", sslLib)):
    inc(curAppId)
    appRoutes = curAppId
    serverHandlerList.add(("appRoutesStage1", ssl, newStmtList()))
    inc(curAppId)
    serverHandlerList.add(("appRoutesStage2", ssl, newStmtList()))
  else:
    inc(curAppId)
    serverHandlerList.add(("appRoutesSend", ssl, newStmtList()))
  var serverResources = newStmtList()
  var routesList = newStmtList()
  for s in body:
    if eqIdent(s[0], "routes"):
      var hostname = ""
      var portInt = intVal(port)
      if s[1].kind == nnkStrLit:
        hostname = $s[1]
        if portInt != 80 and portInt != 443 and not hostname.endsWith(":" & $portInt):
          s[1] = newLit(hostname & ":" & $portInt)
      elif s[1].kind == nnkExprEqExpr and eqIdent(s[1][0], "host"):
        hostname = $s[1][1]
        if portInt != 80 and portInt != 443 and not hostname.endsWith(":" & $portInt):
          s[1][1] = newLit(hostname & ":" & $portInt)
      for i in countdown(hostname.len-1, 0):
        if hostname[i] == ':':
          hostname.setLen(i)
          break
      var routesBase = s.copy()
      var routesBody = newStmtList()
      var certsBlockFlag = false
      for s2 in s[s.len - 1]:
        if eqIdent(s2[0], "certificates"):
          certsBlockFlag = true
          if s2.len > 1:
            if s2[1].kind == nnkStrLit:
              s2[1] = nnkExprEqExpr.newTree(
                newIdentNode("path"),
                newLit("")
              )
            elif s2[1].kind == nnkExprEqExpr:
              if not eqIdent(s2[1][0], "path"):
                s2.insert(1, nnkExprEqExpr.newTree(
                  newIdentNode("path"),
                  newLit("")
                ))
            else:
              s2.insert(1, nnkExprEqExpr.newTree(
                newIdentNode("path"),
                newLit("")
              ))
          else:
            s2.insert(1, nnkExprEqExpr.newTree(
              newIdentNode("path"),
              newLit("")
            ))
          s2.insert(1, nnkExprEqExpr.newTree(
            newIdentNode("site"),
            newLit(hostname)
          ))
          s2.insert(1, nnkExprEqExpr.newTree(
            newIdentNode("srvId"),
            newLit(srvId)
          ))
        elif eqIdent(s2[0], "stream"):
          inc(curAppId)
          var streamAppId = curAppId
          if not eqIdent(s2[1][0], "streamAppId"):
            s2.insert(1, nnkExprEqExpr.newTree(
              newIdentNode("streamAppId"),
              newLit(streamAppId)
            ))
          if s2.len < 5:
            s2.insert(3, nnkExprEqExpr.newTree(
              newIdentNode("protocol"),
              newLit("")
            ))
          serverHandlerList.add(("appStream", ssl, s2[s2.len - 1]))
          inc(curAppId)
          serverHandlerList.add(("appStreamSend", ssl, newStmtList()))
        elif eqIdent(s2[0], "public"):
          var importPath = s2[1]
          inc(curResId)
          var filesTableName = newIdentNode("staticFilesTable" & $curResId)
          var bodyEmpty = false
          if s2.len < 3:
            bodyEmpty = true
            s2.add(newBlockStmt(newStmtList()))
          else:
            s2[2] = newBlockStmt(s2[2])
          s2[2][1].insert 0, quote do:
            template getFile(url: string): FileContentResult =
              `filesTableName`.getStaticFile(url)
          if bodyEmpty:
            s2[2][1].add quote do:
              block:
                var retFile = getFile(reqUrl)
                if retFile.err == FileContentSuccess:
                  return response(retFile.data)
          serverResources.add quote do:
            const `filesTableName` = createStaticFilesTable(`importPath`)
        routesBody.add(s2)

      if not certsBlockFlag and ssl == newLit(true):
        routesBody.insert 0, quote do:
          certificates(`srvId`, `hostname`, "")

      routesBase[routesBase.len - 1] = routesBody
      routesList.add(routesBase)
    else:
      serverWorkerInitStmt.add(s)
    serverHandlerList[appRoutes][2] = routesList

  inc(freePoolServerUsedCount)

  quote do:
    from nativesockets import setBlocking, getSockOptInt, setSockOptInt

    `serverResources`

    var serverSock = createServer(`bindAddress`, `port`)
    addReleaseOnQuit(serverSock)
    serverSock.setBlocking(false)

    if epfd < 0:
      epfd = epoll_create1(O_CLOEXEC)
      if epfd < 0:
        errorRaise "error: epfd=", epfd, " errno=", errno
      addReleaseOnQuit(epfd)

    let newClient = clientFreePool.pop()
    if newClient.isNil:
      raise newException(ServerError, "no free pool")
    newClient.sock = serverSock
    newClient.srvId = `srvId`
    newClient.appId = `appId`
    when cfg.sslLib == None:
      newClient.listenFlag = true
    newClient.ev.events = EPOLLIN or EPOLLEXCLUSIVE
    var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, serverSock, addr newClient.ev)
    if retCtl != 0:
      errorRaise "error: addServer epoll_ctl ret=", retCtl, " ", getErrnoStr()


template addServer*(bindAddress: string, port: uint16, ssl: bool, body: untyped) {.dirty.} =
  initServer()
  when cfg.sslLib == BearSSL:
    addServerMacro(bindAddress, port, ssl, BearSSL, body)
  elif cfg.sslLib == OpenSSL:
    addServerMacro(bindAddress, port, ssl, OpenSSL, body)
  elif cfg.sslLib == LibreSSL:
    addServerMacro(bindAddress, port, ssl, LibreSSL, body)
  elif cfg.sslLib == BoringSSL:
    addServerMacro(bindAddress, port, ssl, BoringSSL, body)
  else:
    addServerMacro(bindAddress, port, ssl, None, body)

macro serverWorkerInit*(): untyped = serverWorkerInitStmt

macro mainServerHandlerMacro*(appId: typed): untyped =
  serverWorkerMainStmt[0][0] = newIdentNode($appId)
  serverWorkerMainStmt


template routes*(host: string, body: untyped) =
  if reqHost() == host:
    block: body

template routes*(body: untyped) =
  block: body

var certsTableData {.compileTime.}: seq[tuple[key: string, val: tuple[
  idx: int, srvId: int, privPath: string, chainPath: string,
  privFileName: string, chainFileName: string]]]

var certsTableDataIdx {.compileTime.}: seq[tuple[key: string, val: int]]

var certsTableIdx {.compileTime.}: int = 1

proc addCertsTable*(site: string, srvId: int, privPath: string, chainPath: string,
                    privFileName: string, chainFileName: string) {.compileTime.} =
  for i, d in certsTableData:
    if d.key == site:
      certsTableData[i].val.privPath = privPath
      certsTableData[i].val.chainPath = chainPath
      certsTableData[i].val.privFileName = privFileName
      certsTableData[i].val.chainFileName = chainFileName
      macros.error "duplicate certificates for the same hostname are not yet supported"
      return
  certsTableData.add((site, (certsTableIdx, srvId, privPath, chainPath,
                    privFileName, chainFileName)))
  certsTableDataIdx.add((site, certsTableIdx))
  inc(certsTableIdx)

macro createCertsTable*(): untyped =
  newStmtList(
    newConstStmt(
      postfix(newIdentNode("staticCertsTable"), "*"),
      newCall("toTable",
        newLit(certsTableData)
      )
    ),
    newConstStmt(
      postfix(newIdentNode("staticCertsIdxTable"), "*"),
      newCall("toTable",
        newLit(certsTableDataIdx)
      )
    )
  )

macro createCertsFileNameList*(): untyped =
  var certsFileNameList: seq[tuple[privFileName, chainFileName: string]]
  certsFileNameList.add(("", ""))
  for d in certsTableData:
    certsFileNameList.add((d.val.privFileName, d.val.chainFileName))
  newConstStmt(
    postfix(newIdentNode("certsFileNameList"), "*"),
    newLit(certsFileNameList)
  )

var certsList: Array[tuple[site: Array[byte], idx: int]]

proc addCertsList*(site: string, idx: int) =
  var a = cast[seq[byte]](site).toArray
  certsList.add((a, idx))

proc getCertsList*(): Array[tuple[site: Array[byte], idx: int]] = certsList

proc getCertIdx*(site: string): int =
  for a in certsList:
    if cast[seq[byte]](site) == a.site:
      return a.idx
  return -1

proc clearCertsList*() = certsList.empty()

template certificates*(path: string, body: untyped) = discard # code is added by macro

template certificates*(body: untyped) = discard # code is added by macro

template acceptKey(key: string): string =
  var sh = sha1.secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  base64.encode(sh.Sha1Digest)

macro onProtocolBodyExists(body: untyped): untyped =
  for s in body:
    if eqIdent(s[0], "onProtocol"):
      return newLit(true)
  return newLit(false)

macro getOnProtocolBody(body: untyped): untyped =
  var onProtocolStmt = newStmtList()
  for s in body:
    if eqIdent(s[0], "onProtocol"):
      onProtocolStmt.add(s[1])
  quote do:
    proc protocolCheck(): tuple[flag: bool, resProtocol: string] =
      `onProtocolStmt`

macro getOnOpenBody(body: untyped): untyped =
  var onOpenStmt = newStmtList()
  for s in body:
    if eqIdent(s[0], "onOpen"):
      onOpenStmt.add(s[1])
  onOpenStmt

template stream*(path: string, protocol: string, body: untyped) = discard # code is added by macro

template stream*(path: string, body: untyped) = discard # code is added by macro

template webSocketMessageProtocol(key, protocol: string): string =
  "HTTP/1.1 " & $Status101 & "\c\L" &
  "Upgrade: websocket\c\L" &
  "Connection: Upgrade\c\L" &
  "Sec-WebSocket-Accept: " & acceptKey(key) & "\c\L" &
  "Sec-WebSocket-Protocol: " & protocol & "\c\L" &
  "Sec-WebSocket-Version: 13\c\L\c\L"

template webSocketMessage(key: string): string =
  "HTTP/1.1 " & $Status101 & "\c\L" &
  "Upgrade: websocket\c\L" &
  "Connection: Upgrade\c\L" &
  "Sec-WebSocket-Accept: " & acceptKey(key) & "\c\L" &
  "Sec-WebSocket-Version: 13\c\L\c\L"

# internal use only
template stream*(streamAppId: int, path: string, protocol: string, body: untyped) =
  if reqUrl() == path:
    let key = getHeaderValue(InternalSecWebSocketKey)
    let ver = getHeaderValue(InternalSecWebSocketVersion)
    if ver.len > 0 and key.len > 0:
      when onProtocolBodyExists(body):
        getOnProtocolBody(body)
        var resProt = protocolCheck()
        if resProt.flag:
          if resProt.resProtocol.len > 0:
            reqClient()[].appId = streamAppId
            let ret = send(webSocketMessageProtocol(key, resProt.resProtocol))
            getOnOpenBody(body)
            return ret
          else:
            reqClient()[].appId = streamAppId
            let ret = send(webSocketMessageProtocol(key))
            getOnOpenBody(body)
            return ret
        else:
          return SendResult.Error
      else:
        when protocol.len > 0:
          let prot = getHeaderValue(InternalSecWebSocketProtocol)
          if prot == protocol:
            reqClient()[].appId = streamAppId
            let ret = send(webSocketMessageProtocol(key, protocol))
            getOnOpenBody(body)
            return ret
          else:
            return SendResult.Error
        else:
          reqClient()[].appId = streamAppId
          let ret = send(webSocketMessageProtocol(key))
          getOnOpenBody(body)
          return ret

template public*(importPath: string, body: untyped) = body

#[
var clientSocketLocks: array[WORKER_THREAD_NUM, cint]
for i in 0..<WORKER_THREAD_NUM:
  clientSocketLocks[i] = osInvalidSocket.cint

var clientSockLock: SpinLock
spinLockInit(clientSockLock)

proc setClientSocketLock(sock: cint, threadId: int): bool {.inline.} =
  withSpinLock clientSockLock:
    for s in clientSocketLocks:
      if s == sock:
        return false
    clientSocketLocks[threadId - 1] = sock
    return true

proc resetClientSocketLock(threadId: int) {.inline.} =
  clientSocketLocks[threadId - 1] = osInvalidSocket.cint
]#

template serverType() {.dirty.} =
  type
    ReqHeader = object
      url: string
      params: array[TargetHeaderParams.len, tuple[cur: int, size: int]]
      minorVer: int

template serverLib(cfg: static Config) {.dirty.} =
  import std/posix
  import std/epoll
  import std/tables
  import std/os
  import std/sha1
  import std/re
  import std/strutils
  import std/sequtils
  import arraylib
  import bytes
  import queue2
  import ptlock
  import logs
  import files

  mixin addSafe, popSafe

  const FreePoolServerUsedCount = freePoolServerUsedCount

  type
    WorkerThreadCtxObj = object
      sockAddress: Sockaddr_in
      addrLen: SockLen
      recvBuf: Array[byte]
      client: Client
      pRecvBuf: ptr UncheckedArray[byte]
      header: ReqHeader
      targetHeaders: Array[ptr tuple[id: HeaderParams, val: string]]
      pRecvBuf0: ptr UncheckedArray[byte]
      threadId: int

    WorkerThreadCtx = ptr WorkerThreadCtxObj
    ClientHandlerProc = proc (ctx: WorkerThreadCtx) {.thread.}

  var workerThreadCtx {.threadvar.}: WorkerThreadCtx
  #var clientHandlerProcs: Array[ClientHandlerProc]

  var clientQueue = queue2.newQueue[Client](0x10000)
  var highGearManagerAssinged: int = 0
  var highGearSemaphore: Sem
  discard sem_init(addr highGearSemaphore, 0, 0)
  #discard sem_destroy(addr highGearSemaphore)
  var throttleBody: Sem
  discard sem_init(addr throttleBody, 0, 0)
  #discard sem_destroy(addr throttleBody)
  var throttleChanged: bool = false
  var highGearThreshold: int

  proc atomic_compare_exchange_n(p: ptr int, expected: ptr int, desired: int, weak: bool,
                                success_memmodel: int, failure_memmodel: int): bool
                                {.importc: "__atomic_compare_exchange_n", nodecl, discardable.}

  proc atomic_fetch_add(p: ptr int, val: int, memmodel: int): int
                          {.importc: "__atomic_fetch_add", nodecl, discardable.}

  proc atomic_fetch_sub(p: ptr int, val: int, memmodel: int): int
                          {.importc: "__atomic_fetch_sub", nodecl, discardable.}

  macro certificates*(srvId: int, site: string, path: string, body: untyped = newEmptyNode()): untyped =
    var srvId = intVal(srvId).int
    var site = $site
    var path = $path
    var priv, chain: string
    var privPath, chainPath: string
    for s in body:
      if s.kind == nnkCall:
        if eqIdent(s[0], "privKey"):
          priv = $s[1][0]
        elif eqIdent(s[0], "fullChain"):
          chain = $s[1][0]
    if path.len == 0:
      path = cfg.certsPath / site
    if priv.len == 0:
      priv = cfg.privKeyFile
    if chain.len == 0:
      chain = cfg.fullChainFile
    if path.len > 0:
      if priv == splitPath(priv).tail:
        privPath = path / priv
      else:
        privPath = priv
      if chain == splitPath(chain).tail:
        chainPath = path / chain
      else:
        chainPath = chain
    else:
      privPath = priv
      chainPath = chain
      priv = splitPath(privPath).tail
      chain = splitPath(chainPath).tail
    addCertsTable(site, srvId, privPath, chainPath, priv, chain)

  proc echoHeader(buf: ptr UncheckedArray[byte], size: int, header: ReqHeader) =
    echo "url: ", header.url
    for i, param in header.params:
      echo i.HeaderParams, " ", TargetHeaderParams[i], cast[ptr UncheckedArray[byte]](addr buf[param.cur]).toString(param.size)

  proc getHeaderValue(buf: ptr UncheckedArray[byte], reqHeader: ReqHeader, paramId: HeaderParams): string =
    let param = reqHeader.params[paramId.int]
    result = cast[ptr UncheckedArray[byte]](addr buf[param.cur]).toString(param.size)

  proc parseHeader(buf: ptr UncheckedArray[byte], size: int,
                  targetHeaders: var Array[ptr tuple[id: HeaderParams, val: string]]
                  ): tuple[err: int, header: ReqHeader, next: int] =
    if equalMem(addr buf[0], "GET /".cstring, 5):
      var cur = 4
      var pos = 5
      while true:
        if equalMem(addr buf[pos], " HTTP/1.".cstring, 8):
          result.header.url = cast[ptr UncheckedArray[byte]](addr buf[cur]).toString(pos - cur)
          inc(pos, 8)
          if equalMem(addr buf[pos], "1\c\L".cstring, 3):
            result.header.minorVer = 1
            inc(pos, 3)
          elif equalMem(addr buf[pos], "0\c\L".cstring, 3):
            result.header.minorVer = 0
            inc(pos, 3)
          else:
            let minorVer = int(buf[pos]) - int('0')
            if minorVer < 0 or minorVer > 9:
              result.err = 4
              result.next = -1
              return
            inc(pos)
            if not equalMem(addr buf[pos], "\c\L".cstring, 2):
              result.err = 5
              result.next = -1
              return
            inc(pos, 2)
            result.header.minorVer = minorVer
          if equalMem(addr buf[pos], "\c\L".cstring, 2):
            result.next = pos + 2
            return

          var incompleteIdx = 0
          while true:
            block paramsLoop:
              for i in incompleteIdx..<targetHeaders.len:
                let (headerId, targetParam) = targetHeaders[i][]
                if equalMem(addr buf[pos], targetParam.cstring, targetParam.len):
                  inc(pos, targetParam.len)
                  cur = pos
                  while not equalMem(addr buf[pos], "\c\L".cstring, 2):
                    inc(pos)
                  result.header.params[headerId.int] = (cur, pos - cur)
                  inc(pos, 2)
                  if equalMem(addr buf[pos], "\c\L".cstring, 2):
                    result.next = pos + 2
                    return
                  if i != incompleteIdx:
                    swap(targetHeaders[incompleteIdx], targetHeaders[i])
                  inc(incompleteIdx)
                  if incompleteIdx >= targetHeaders.len:
                    inc(pos)
                    while(not equalMem(addr buf[pos], "\c\L\c\L".cstring, 4)):
                      inc(pos)
                    result.next = pos + 4
                    return
                  break paramsLoop
              while not equalMem(addr buf[pos], "\c\L".cstring, 2):
                inc(pos)
              inc(pos, 2)
              if equalMem(addr buf[pos], "\c\L".cstring, 2):
                result.next = pos + 2
                return

        elif equalMem(addr buf[pos], "\c\L".cstring, 2):
          result.err = 3
          result.next = -1
          return
        inc(pos)
    else:
      result.err = 2
      result.next = -1


  proc getFrame(data: ptr UncheckedArray[byte],
                size: int): tuple[find: bool, fin: bool, opcode: int8,
                                  payload: ptr UncheckedArray[byte], payloadSize: int,
                                  next: ptr UncheckedArray[byte], size: int] =
    if size < 2:
      return (false, false, -1.int8, nil, 0, data, size)

    var b1 = data[1]
    var mask = ((b1 and 0x80.byte) != 0)
    if not mask:
      raise newException(ServerError, "websocket client no mask")
    var b0 = data[0]
    var fin = ((b0 and 0xf0.byte) == 0x80.byte)
    var opcode = (b0 and 0x0f.byte).int8

    var payloadLen = (b1 and 0x7f.byte).int
    var frameHeadSize {.noInit.}: int
    if payloadLen < 126:
      frameHeadSize = 6
    elif payloadLen == 126:
      if size < 4:
        return (false, fin, opcode, nil, 0, data, size)
      payloadLen = data[2].toUint16BE.int
      frameHeadSize = 8
    elif payloadLen == 127:
      if size < 10:
        return (false, fin, opcode, nil, 0, data, size)
      payloadLen = data[2].toUint64BE.int # exception may occur. value out of range [RangeDefect]
      frameHeadSize = 14
    else:
      return (false, fin, opcode, nil, 0, data, size)

    var frameSize = frameHeadSize + payloadLen
    if frameSize > cfg.maxFrameSize:
      raise newException(ServerError, "websocket frame size is too big frameSize=" & $frameSize)

    if size < frameSize:
      return (false, fin, opcode, nil, 0, data, size)

    var maskData {.noInit.}: array[4, byte]
    copyMem(addr maskData[0], addr data[frameHeadSize - 4], 4)
    var payload = cast[ptr UncheckedArray[byte]](addr data[frameHeadSize])
    for i in 0..<payloadLen:
      payload[i] = payload[i] xor maskData[i mod 4]

    if size > frameSize:
      return (true, fin, opcode, payload, payloadLen, cast[ptr UncheckedArray[byte]](addr data[frameSize]), size - frameSize)
    else:
      return (true, fin, opcode, payload, payloadLen, nil, 0)

  template headerUrl(): string {.dirty.} = ctx.header.url

  template get(path: string, body: untyped) {.dirty.} =
    if headerUrl() == path:
      body

  template get(pathArgs: varargs[string], body: untyped) {.dirty.} =
    if headerUrl() in pathArgs:
      body

  template get(path: Regex, body: untyped) {.dirty.} =
    if headerUrl() =~ path:
      body

  template acme(path: static string, body: untyped) {.dirty.} =
    block:
      var (acmeFlag, content, mime) = getAcmeChallenge(path, ctx.header.url)
      if acmeFlag:
        body
        if content.len > 0:
          return send(content.addHeader(Status200, mime))

  template acme(path: static string) {.dirty.} =
    block:
      var (acmeFlag, content, mime) = getAcmeChallenge(path, ctx.header.url)
      if content.len > 0:
        return send(content.addHeader(Status200, mime))

  template reqUrl: string {.dirty.} = ctx.header.url

  template reqClient: Client {.dirty.} = ctx.client

  template reqHost: string {.dirty.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, InternalEssentialHeaderHost)

  template reqProtocol: string {.dirty.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, InternalSecWebSocketProtocol)

  template reqHeader(paramId: HeaderParams): string {.dirty.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, paramId)

  template getHeaderValue(paramId: HeaderParams): string {.dirty.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, paramId)

  template response(file: FileContent): SendResult =
    if reqHeader(InternalIfNoneMatch) == file.md5:
      send(Empty.addHeader(Status304))
    else:
      var acceptEnc = reqHeader(InternalAcceptEncoding).split(",")
      acceptEnc.apply(proc(x: string): string = x.strip)
      if acceptEnc.contains("br"):
        send(file.brotli.addHeaderBrotli(file.md5, Status200, file.mime))
      elif acceptEnc.contains("deflate"):
        send(file.deflate.addHeaderDeflate(file.md5, Status200, file.mime))
      else:
        send(file.content.addHeader(file.md5, Status200, file.mime))

  proc mainServerHandler(ctx: WorkerThreadCtx, client: Client, pRecvBuf: ptr UncheckedArray[byte], header: ReqHeader): SendResult {.inline.} =
    let appId = client.appId - 1
    mainServerHandlerMacro(appId)

  proc appDummy(ctx: WorkerThreadCtx) {.thread.} = discard

  var certsTable: ptr Table[string, tuple[idx: int, srvId: int,
                            privPath: string, chainPath: string,
                            privFileName: string, chainFileName: string]]
  var certsIdxTable: ptr Table[string, int]

  when cfg.sslLib == BearSSL:
    type
      uint16_t = uint16

    type
      PemObj = object
        name: string
        data: seq[byte]

      PemObjs = seq[PemObj]

    proc decodePem(pemData: string): PemObjs =
      var pemData = pemData
      if pemData[pemData.len - 1] != '\n':
        pemData.add("\n")

      var pc: br_pem_decoder_context
      br_pem_decoder_init(addr pc)

      proc dest(dest_ctx: pointer; src: pointer; len: csize_t) {.cdecl.} =
        let pBuf = cast[ptr seq[byte]](dest_ctx)
        let srcBytes = cast[ptr UncheckedArray[byte]](src).toBytes(len)
        pBuf[].add(srcBytes)

      var buf: seq[byte] = @[]
      br_pem_decoder_setdest(addr pc, dest, cast[pointer](addr buf))

      var len = pemData.len
      var pos = 0
      var pemObj: PemObj

      while len > 0:
        var tlen = br_pem_decoder_push(addr pc, addr pemData[pos], len.csize_t).int
        dec(len, tlen)
        inc(pos, tlen)
        case br_pem_decoder_event(addr pc)
        of BR_PEM_BEGIN_OBJ:
          pemObj.name = $br_pem_decoder_name(addr pc)
        of BR_PEM_END_OBJ:
          if buf.len > 0:
            pemObj.data = buf
            zeroMem(addr buf[0], buf.len)
            buf = @[]
            result.add(pemObj)
            zeroMem(addr pemObj.name[0], pemObj.name.len)
            pemObj.name = ""
            zeroMem(addr pemObj.data[0], pemObj.data.len)
            pemObj.data = @[]
        of BR_PEM_ERROR:
          raise
        else:
          raise

    proc clearPemObjs(pemObjs: var PemObjs) =
      for i in 0..<pemObjs.len:
        zeroMem(addr pemObjs[i].name[0], pemObjs[i].name.len)
        pemObjs[i].name = ""
        zeroMem(addr pemObjs[i].data[0], pemObjs[i].data.len)
        pemObjs[i].data = @[]
      pemObjs = @[]

    type
      CertPrivateKeyType* {.pure.} = enum
        None
        RSA
        EC

      CertPrivateKey* = object
        case type*: CertPrivateKeyType
        of CertPrivateKeyType.None:
          discard
        of CertPrivateKeyType.RSA:
          rsa*: ptr br_rsa_private_key
        of CertPrivateKeyType.EC:
          ec*: ptr br_ec_private_key

    proc decodeCertPrivateKey(data: seq[byte]): CertPrivateKey =
      var dc: br_skey_decoder_context
      br_skey_decoder_init(addr dc)
      br_skey_decoder_push(addr dc, unsafeAddr data[0], data.len.csize_t)
      let err = br_skey_decoder_last_error(addr dc)
      if err != 0:
        return CertPrivateKey(type: CertPrivateKeyType.None)

      let keyType = br_skey_decoder_key_type(addr dc)
      case keyType
      of BR_KEYTYPE_RSA:
        var rk = br_skey_decoder_get_rsa(addr dc)
        var sk = cast[ptr br_rsa_private_key](allocShared0(sizeof(br_rsa_private_key)))
        sk.n_bitlen = rk.n_bitlen
        sk.p = cast[ptr uint8](allocShared0(rk.plen))
        copyMem(sk.p, rk.p, rk.plen)
        sk.plen = rk.plen
        sk.q = cast[ptr uint8](allocShared0(rk.qlen))
        copyMem(sk.q, rk.q, rk.qlen)
        sk.qlen = rk.qlen
        sk.dp = cast[ptr uint8](allocShared0(rk.dplen))
        copyMem(sk.dp, rk.dp, rk.dplen)
        sk.dplen = rk.dplen
        sk.dq = cast[ptr uint8](allocShared0(rk.dqlen))
        copyMem(sk.dq, rk.dq, rk.dqlen)
        sk.dqlen = rk.dqlen
        sk.iq = cast[ptr uint8](allocShared0(rk.iqlen))
        copyMem(sk.iq, rk.iq, rk.iqlen)
        sk.iqlen = rk.iqlen
        zeroMem(addr dc, sizeof(br_skey_decoder_context))
        return CertPrivateKey(type: CertPrivateKeyType.RSA, rsa: sk)

      of BR_KEYTYPE_EC:
        var ek = br_skey_decoder_get_ec(addr dc)
        var sk = cast[ptr br_ec_private_key](allocShared0(sizeof(br_ec_private_key)))
        sk.curve = ek.curve
        sk.x = cast[ptr uint8](allocShared0(ek.xlen))
        copyMem(sk.x, ek.x, ek.xlen)
        sk.xlen = ek.xlen
        zeroMem(addr dc, sizeof(br_skey_decoder_context))
        return CertPrivateKey(type: CertPrivateKeyType.EC, ec: sk)

      else:
        return CertPrivateKey(type: CertPrivateKeyType.None)

    proc freeCertPrivateKey(certPrivKey: var CertPrivateKey) =
      case certPrivKey.type
      of CertPrivateKeyType.RSA:
        if not certPrivKey.rsa.isNil:
          zeroMem(certPrivKey.rsa.iq, certPrivKey.rsa.iqlen)
          zeroMem(certPrivKey.rsa.dq, certPrivKey.rsa.dqlen)
          zeroMem(certPrivKey.rsa.dp, certPrivKey.rsa.dplen)
          zeroMem(certPrivKey.rsa.q, certPrivKey.rsa.qlen)
          zeroMem(certPrivKey.rsa.p, certPrivKey.rsa.plen)
          deallocShared(certPrivKey.rsa.iq)
          deallocShared(certPrivKey.rsa.dq)
          deallocShared(certPrivKey.rsa.dp)
          deallocShared(certPrivKey.rsa.q)
          deallocShared(certPrivKey.rsa.p)
          zeroMem(certPrivKey.rsa, sizeof(br_rsa_private_key))
          deallocShared(certPrivKey.rsa)
          certPrivKey.rsa = nil
          certPrivKey = CertPrivateKey(type: CertPrivateKeyType.None)

      of CertPrivateKeyType.EC:
        if not certPrivKey.ec.isNil:
          zeroMem(certPrivKey.ec.x, certPrivKey.ec.xlen)
          deallocShared(certPrivKey.ec.x)
          zeroMem(certPrivKey.ec, sizeof(br_ec_private_key))
          deallocShared(certPrivKey.ec)
          certPrivKey.ec = nil
          certPrivKey = CertPrivateKey(type: CertPrivateKeyType.None)

      of CertPrivateKeyType.None:
        discard

    type
      X509CertificateChains = object
        cert: ptr UncheckedArray[br_x509_certificate]
        certLen: csize_t

    proc createChains(pemData: string): X509CertificateChains =
      var pemData = pemData
      if pemData[pemData.len - 1] != '\n':
        pemData.add("\n")

      var pc: br_pem_decoder_context
      br_pem_decoder_init(addr pc)

      proc dest(dest_ctx: pointer; src: pointer; len: csize_t) {.cdecl.} =
        let pBuf = cast[ptr seq[byte]](dest_ctx)
        let srcBytes = cast[ptr UncheckedArray[byte]](src).toBytes(len)
        pBuf[].add(srcBytes)

      var allBuf: seq[seq[byte]]
      var buf: seq[byte]
      br_pem_decoder_setdest(addr pc, dest, cast[pointer](addr buf))

      var len = pemData.len
      var pos = 0

      while len > 0:
        var tlen = br_pem_decoder_push(addr pc, addr pemData[pos], len.csize_t).int
        dec(len, tlen)
        inc(pos, tlen)
        case br_pem_decoder_event(addr pc)
        of BR_PEM_BEGIN_OBJ:
          buf = @[]
        of BR_PEM_END_OBJ:
          allBuf.add(buf)
        of BR_PEM_ERROR:
          raise
        else:
          raise

      result.cert = cast[ptr UncheckedArray[br_x509_certificate]](allocShared0(sizeof(br_x509_certificate) * allBuf.len))
      result.certLen = allBuf.len.csize_t
      for i, b in allBuf:
        result.cert[i].data = cast[ptr uint8](allocShared0(b.len))
        result.cert[i].data_len = b.len.csize_t
        copyMem(result.cert[i].data, unsafeAddr b[0], b.len)

    proc freeChains(chains: var X509CertificateChains) =
      for i in 0..<chains.certLen:
        chains.cert[i].data_len = 0
        if not chains.cert[i].data.isNil:
          deallocShared(chains.cert[i].data)
          chains.cert[i].data = nil
      chains.certLen = 0
      if not chains.cert.isNil:
        deallocShared(chains.cert)
        chains.cert = nil

    var certKeyChainsList: Array[tuple[key: CertPrivateKey, chains: X509CertificateChains]]
    var certKeyChainsListLock: Lock
    initLock(certKeyChainsListLock)
    #deinitLock(certKeyChainsListLock)

    let suites = [uint16_t BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                  BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256]

    proc br_ssl_choose_hash(bf: cuint): cint {.importc, cdecl, gcsafe.}

    proc sr_choose(pctx: ptr ptr br_ssl_server_policy_class;
      cc: ptr br_ssl_server_context; choices: ptr br_ssl_server_choices): cint {.cdecl.} =
      var pc = cast[ptr br_ssl_server_policy_rsa_context](pctx)
      let st = addr cc.client_suites
      let st_num = cc.client_suites_num.csize_t
      var hash_id: cuint
      var fh: bool
      if cc.eng.session.version < BR_TLS12:
        hash_id = 0.cuint
        fh = true
      else:
        hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc).cuint).cuint
        fh = (hash_id != 0)
      choices.chain = pc.chain
      choices.chain_len = pc.chain_len
      for u in 0..<st_num:
        var tt = st[u][1]
        case tt shr 12
        of BR_SSLKEYX_RSA:
          if (pc.allowed_usages and BR_KEYTYPE_KEYX) != 0:
            choices.cipher_suite = st[u][0]
            return 1.cint
        of BR_SSLKEYX_ECDHE_RSA:
          if (pc.allowed_usages and BR_KEYTYPE_SIGN) != 0 and fh:
            choices.cipher_suite = st[u][0]
            choices.algo_id = hash_id + 0xFF00
            return 1.cint
        else:
          continue
      return 0.cint

    proc sr_do_keyx(pctx: ptr ptr br_ssl_server_policy_class; data: ptr uint8;
                    len: ptr csize_t): uint32 {.cdecl.}  =
      var pc = cast[ptr br_ssl_server_policy_rsa_context](pctx)
      return br_rsa_ssl_decrypt(pc.irsacore, pc.sk, data, len[])

    const HASH_OID_SHA1 = @[uint8 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A]
    const HASH_OID_SHA224 = @[uint8 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]
    const HASH_OID_SHA256 = @[uint8 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    const HASH_OID_SHA384 = @[uint8 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]
    const HASH_OID_SHA512 = @[uint8 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]
    const HASH_OID = @[
      HASH_OID_SHA1,
      HASH_OID_SHA224,
      HASH_OID_SHA256,
      HASH_OID_SHA384,
      HASH_OID_SHA512
    ]

    proc sr_do_sign(pctx: ptr ptr br_ssl_server_policy_class; algo_id: cuint;
                    data: ptr uint8; hv_len: csize_t; len: csize_t): csize_t {.cdecl.} =
      var pc = cast[ptr br_ssl_server_policy_rsa_context](pctx)
      var hv: array[64, uint8]
      var hash_oid: ptr uint8
      copyMem(addr hv, data, hv_len.int)
      var algo_id = (algo_id and 0xff).cint
      if algo_id == 0:
        hash_oid = cast[ptr uint8](nil)
      elif algo_id >= 2 and algo_id <= 6:
        hash_oid = cast[ptr uint8](unsafeAddr HASH_OID[algo_id - 2][0])
      else:
        return 0.csize_t
      var sig_len: csize_t = (pc.sk.n_bitlen + 7) shr 3
      if len < sig_len:
        return 0.csize_t
      if pc.irsasign(hash_oid, cast[ptr uint8](addr hv), hv_len, pc.sk, data) > 0:
        return sig_len
      else:
        return 0.csize_t

    var sr_policy_vtable_obj = br_ssl_server_policy_class(
      context_size: sizeof(br_ssl_server_policy_rsa_context).csize_t,
      choose: sr_choose,
      do_keyx: sr_do_keyx,
      do_sign: sr_do_sign
    )

    proc br_ssl_server_set_single_rsa_caprese*(cc: ptr br_ssl_server_context;
                                               chain: ptr br_x509_certificate;
                                               chain_len: csize_t; sk: ptr br_rsa_private_key;
                                               allowed_usages: cuint;
                                               irsacore: br_rsa_private;
                                               irsasign: br_rsa_pkcs1_sign) =
      cc.chain_handler.single_rsa.vtable = addr sr_policy_vtable_obj
      cc.chain_handler.single_rsa.chain = chain
      cc.chain_handler.single_rsa.chain_len = chain_len
      cc.chain_handler.single_rsa.sk = sk
      cc.chain_handler.single_rsa.allowed_usages = allowed_usages
      cc.chain_handler.single_rsa.irsacore = irsacore
      cc.chain_handler.single_rsa.irsasign = irsasign
      cc.policy_vtable = addr cc.chain_handler.single_rsa.vtable

    proc se_choose(pctx: ptr ptr br_ssl_server_policy_class;
      cc: ptr br_ssl_server_context; choices: ptr br_ssl_server_choices): cint {.cdecl.} =
      var pc = cast[ptr br_ssl_server_policy_ec_context](pctx)
      let st = addr cc.client_suites
      let st_num = cc.client_suites_num.csize_t
      var hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc).cuint shr 8).cuint
      if cc.eng.session.version < BR_TLS12:
        hash_id = br_sha1_ID
      choices.chain = pc.chain
      choices.chain_len = pc.chain_len
      for u in 0..<st_num:
        var tt = st[u][1]
        case tt shr 12
        of BR_SSLKEYX_ECDH_RSA:
          if (pc.allowed_usages and BR_KEYTYPE_KEYX) != 0 and
            pc.cert_issuer_key_type == BR_KEYTYPE_RSA:
            choices.cipher_suite = st[u][0]
            return 1.cint
        of BR_SSLKEYX_ECDH_ECDSA:
          if (pc.allowed_usages and BR_KEYTYPE_KEYX) != 0 and
            pc.cert_issuer_key_type == BR_KEYTYPE_EC:
            choices.cipher_suite = st[u][0]
            return 1.cint
        of BR_SSLKEYX_ECDHE_ECDSA:
          if (pc.allowed_usages and BR_KEYTYPE_SIGN) != 0 and hash_id != 0:
            choices.cipher_suite = st[u][0]
            choices.algo_id = hash_id + 0xFF00
            return 1.cint
        else:
          continue
      return 0.cint

    proc se_do_keyx(pctx: ptr ptr br_ssl_server_policy_class; data: ptr uint8;
                    len: ptr csize_t): uint32 {.cdecl.}  =
      var pc = cast[ptr br_ssl_server_policy_ec_context](pctx)
      var r = pc.iec.mul(data, len[], pc.sk.x, pc.sk.xlen, pc.sk.curve)
      var xlen: csize_t
      var xoff = pc.iec.xoff(pc.sk.curve, addr xlen)
      moveMem(data, addr cast[ptr UncheckedArray[uint8]](data)[xoff], xlen)
      len[] = xlen
      return r

    proc se_do_sign(pctx: ptr ptr br_ssl_server_policy_class; algo_id: cuint;
                    data: ptr uint8; hv_len: csize_t; len: csize_t): csize_t {.cdecl.} =
      var a: array[128, byte]
      for i in 0..<128:
        a[i] = 5
      a[0] = 3
      var alen: csize_t
      var hv: array[64, char]
      var algo_id = (algo_id and 0xff).cint
      var pc = cast[ptr br_ssl_server_policy_ec_context](pctx)
      var hc = br_multihash_getimpl(pc.mhash, algo_id)
      if hc.isNil:
        return 0.csize_t
      copyMem(addr hv, data, hv_len.int)
      if len < 139:
        return 0
      return pc.iecdsa(pc.iec, hc, addr hv, pc.sk, data)

    var se_policy_vtable_obj = br_ssl_server_policy_class(
      context_size: sizeof(br_ssl_server_policy_ec_context).csize_t,
      choose: se_choose,
      do_keyx: se_do_keyx,
      do_sign: se_do_sign
    )

    proc br_ssl_server_set_single_ec_caprese*(cc: ptr br_ssl_server_context;
                                             chain: ptr br_x509_certificate;
                                             chain_len: csize_t; sk: ptr br_ec_private_key;
                                             allowed_usages: cuint;
                                             cert_issuer_key_type: cuint; iec: ptr br_ec_impl;
                                             iecdsa: br_ecdsa_sign) =
      cc.chain_handler.single_ec.vtable = addr se_policy_vtable_obj
      cc.chain_handler.single_ec.chain = chain
      cc.chain_handler.single_ec.chain_len = chain_len
      cc.chain_handler.single_ec.sk = sk
      cc.chain_handler.single_ec.allowed_usages = allowed_usages
      cc.chain_handler.single_ec.cert_issuer_key_type = cert_issuer_key_type
      cc.chain_handler.single_ec.mhash = addr cc.eng.mhash
      cc.chain_handler.single_ec.iec = iec
      cc.chain_handler.single_ec.iecdsa = iecdsa
      cc.policy_vtable = addr cc.chain_handler.single_ec.vtable

    proc sa_choose(pctx: ptr ptr br_ssl_server_policy_class;
      cc: ptr br_ssl_server_context; choices: ptr br_ssl_server_choices): cint {.cdecl.} =
      let serverName = $br_ssl_engine_get_server_name(addr cc.eng)
      debug "br_ssl_engine_get_server_name=", serverName

      var idx = certsIdxTable[].getOrDefault(serverName)
      var certKeyChains = addr certKeyChainsList[idx]
      if certKeyChains[].key.type == CertPrivateKeyType.None:
        debug "CertPrivateKeyType.None serverName=", serverName
        certKeyChains = addr certKeyChainsList[0]
      acquire(certKeyChainsListLock)
      let certKey = certKeyChains[].key
      let chains = certKeyChains[].chains
      release(certKeyChainsListLock)

      case certKey.type
      of CertPrivateKeyType.EC:
        workerThreadCtx.client.keyType = BR_KEYTYPE_EC
        cc.chain_handler.single_ec.chain = cast[ptr br_x509_certificate](chains.cert)
        cc.chain_handler.single_ec.chain_len = chains.certLen
        cc.chain_handler.single_ec.sk = certKey.ec
        cc.chain_handler.single_ec.allowed_usages = BR_KEYTYPE_SIGN
        cc.chain_handler.single_ec.cert_issuer_key_type = 0.cuint
        cc.chain_handler.single_ec.mhash = addr cc.eng.mhash
        cc.chain_handler.single_ec.iec = addr br_ec_all_m15
        cc.chain_handler.single_ec.iecdsa = cast[br_ecdsa_sign](br_ecdsa_i31_sign_asn1)

        var pc = cast[ptr br_ssl_server_policy_ec_context](pctx)
        let st = addr cc.client_suites
        let st_num = cc.client_suites_num.csize_t
        var hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc).cuint shr 8).cuint
        if cc.eng.session.version < BR_TLS12:
          hash_id = br_sha1_ID
        choices.chain = pc.chain
        choices.chain_len = pc.chain_len
        for u in 0..<st_num:
          var tt = st[u][1]
          case tt shr 12
          of BR_SSLKEYX_ECDH_RSA:
            if (pc.allowed_usages and BR_KEYTYPE_KEYX) != 0 and
              pc.cert_issuer_key_type == BR_KEYTYPE_RSA:
              choices.cipher_suite = st[u][0]
              return 1.cint
          of BR_SSLKEYX_ECDH_ECDSA:
            if (pc.allowed_usages and BR_KEYTYPE_KEYX) != 0 and
              pc.cert_issuer_key_type == BR_KEYTYPE_EC:
              choices.cipher_suite = st[u][0]
              return 1.cint
          of BR_SSLKEYX_ECDHE_ECDSA:
            if (pc.allowed_usages and BR_KEYTYPE_SIGN) != 0 and hash_id != 0:
              choices.cipher_suite = st[u][0]
              choices.algo_id = hash_id + 0xFF00
              return 1.cint
          else:
            continue
        return 0.cint

      of CertPrivateKeyType.RSA:
        workerThreadCtx.client.keyType = BR_KEYTYPE_RSA
        cc.chain_handler.single_rsa.chain = cast[ptr br_x509_certificate](chains.cert)
        cc.chain_handler.single_rsa.chain_len = chains.certLen
        cc.chain_handler.single_rsa.sk = certKey.rsa
        cc.chain_handler.single_rsa.allowed_usages = BR_KEYTYPE_SIGN
        cc.chain_handler.single_rsa.irsacore = cast[br_rsa_private](0)
        cc.chain_handler.single_rsa.irsasign = br_rsa_i31_pkcs1_sign

        var pc = cast[ptr br_ssl_server_policy_rsa_context](pctx)
        let st = addr cc.client_suites
        let st_num = cc.client_suites_num.csize_t
        var hash_id: cuint
        var fh: bool
        if cc.eng.session.version < BR_TLS12:
          hash_id = 0.cuint
          fh = true
        else:
          hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc).cuint).cuint
          fh = (hash_id != 0)
        choices.chain = pc.chain
        choices.chain_len = pc.chain_len
        for u in 0..<st_num:
          var tt = st[u][1]
          case tt shr 12
          of BR_SSLKEYX_RSA:
            if (pc.allowed_usages and BR_KEYTYPE_KEYX) != 0:
              choices.cipher_suite = st[u][0]
              return 1.cint
          of BR_SSLKEYX_ECDHE_RSA:
            if (pc.allowed_usages and BR_KEYTYPE_SIGN) != 0 and fh:
              choices.cipher_suite = st[u][0]
              choices.algo_id = hash_id + 0xFF00
              return 1.cint
          else:
            continue
        return 0.cint

      else:
        raise

    proc sa_do_keyx(pctx: ptr ptr br_ssl_server_policy_class; data: ptr uint8;
                    len: ptr csize_t): uint32 {.cdecl.}  =
      case workerThreadCtx.client.keyType
      of BR_KEYTYPE_EC:
        var pc = cast[ptr br_ssl_server_policy_ec_context](pctx)
        var r = pc.iec.mul(data, len[], pc.sk.x, pc.sk.xlen, pc.sk.curve)
        var xlen: csize_t
        var xoff = pc.iec.xoff(pc.sk.curve, addr xlen)
        moveMem(data, addr cast[ptr UncheckedArray[uint8]](data)[xoff], xlen)
        len[] = xlen
        return r

      of BR_KEYTYPE_RSA:
        var pc = cast[ptr br_ssl_server_policy_rsa_context](pctx)
        return br_rsa_ssl_decrypt(pc.irsacore, pc.sk, data, len[])

      else:
        raise

    proc sa_do_sign(pctx: ptr ptr br_ssl_server_policy_class; algo_id: cuint;
                    data: ptr uint8; hv_len: csize_t; len: csize_t): csize_t {.cdecl.} =
      case workerThreadCtx.client.keyType
      of BR_KEYTYPE_EC:
        var a: array[128, byte]
        for i in 0..<128:
          a[i] = 5
        a[0] = 3
        var alen: csize_t
        var hv: array[64, char]
        var algo_id = (algo_id and 0xff).cint
        var pc = cast[ptr br_ssl_server_policy_ec_context](pctx)
        var hc = br_multihash_getimpl(pc.mhash, algo_id)
        if hc.isNil:
          return 0.csize_t
        copyMem(addr hv, data, hv_len.int)
        if len < 139:
          return 0
        return pc.iecdsa(pc.iec, hc, addr hv, pc.sk, data)

      of BR_KEYTYPE_RSA:
        var pc = cast[ptr br_ssl_server_policy_rsa_context](pctx)
        var hv: array[64, uint8]
        var hash_oid: ptr uint8
        copyMem(addr hv, data, hv_len.int)
        var algo_id = (algo_id and 0xff).cint
        if algo_id == 0:
          hash_oid = cast[ptr uint8](nil)
        elif algo_id >= 2 and algo_id <= 6:
          hash_oid = cast[ptr uint8](unsafeAddr HASH_OID[algo_id - 2][0])
        else:
          return 0.csize_t
        var sig_len: csize_t = (pc.sk.n_bitlen + 7) shr 3
        if len < sig_len:
          return 0.csize_t
        if pc.irsasign(hash_oid, cast[ptr uint8](addr hv), hv_len, pc.sk, data) > 0:
          return sig_len
        else:
          return 0.csize_t

      else:
        raise

    var sa_policy_vtable_obj = br_ssl_server_policy_class(
      #context_size: 0.csize_t,
      choose: sa_choose,
      do_keyx: sa_do_keyx,
      do_sign: sa_do_sign
    )

    proc br_ssl_server_init_caprese(cc: ptr br_ssl_server_context) =
      br_ssl_server_zero(cc)
      br_ssl_engine_set_versions(addr cc.eng, BR_TLS12, BR_TLS12)
      br_ssl_engine_set_suites(addr cc.eng, unsafeAddr suites[0], suites.len.csize_t)
      br_ssl_engine_set_ec(addr cc.eng, addr br_ec_all_m15)
      cc.chain_handler.vtable = addr sa_policy_vtable_obj
      cc.policy_vtable = addr cc.chain_handler.vtable
      #br_ssl_server_set_single_rsa_caprese(cc, cast[ptr br_x509_certificate](unsafeAddr CHAIN[0]),
      #  CHAIN_LEN.csize_t, cast[ptr br_rsa_private_key](unsafeAddr RSA),
      #  BR_KEYTYPE_SIGN, cast[br_rsa_private](0), br_rsa_i31_pkcs1_sign)
      #br_ssl_server_set_single_ec_caprese(cc, cast[ptr br_x509_certificate](unsafeAddr CHAIN[0]),
      #  CHAIN_LEN.csize_t, cast[ptr br_ec_private_key](unsafeAddr EC), BR_KEYTYPE_SIGN, 0,
      #  addr br_ec_all_m15, cast[br_ecdsa_sign](br_ecdsa_i31_sign_asn1))
      br_ssl_engine_set_hash(addr cc.eng, br_sha256_ID, addr br_sha256_vtable)
      br_ssl_engine_set_prf_sha256(addr cc.eng, br_tls12_sha256_prf)
      br_ssl_engine_set_default_chapol(addr cc.eng)

  elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
    import std/os
    import std/tables
    import std/strutils

    proc selfSignedCertificate(ctx: SSL_CTX) =
      var x509: X509 = X509_new()
      var pkey: EVP_PKEY = EVP_PKEY_new()
      var rsa: RSA = RSA_new()
      var exp: BIGNUM = BN_new()
      var big: BIGNUM = BN_new()
      var serial: ASN1_INTEGER = ASN1_INTEGER_new()

      defer:
        ASN1_INTEGER_free(serial)
        BN_free(big)
        BN_free(exp)
        if not rsa.isNil: RSA_free(rsa)
        EVP_PKEY_free(pkey)
        X509_free(x509)

      template checkErr(err: cint) {.dirty.} =
        if err == 0:
          raise newException(ServerSslCertError, "self certificate check error")

      checkErr BN_set_word(exp, RSA_F4)
      checkErr RSA_generate_key_ex(rsa, 2048, exp, nil)
      checkErr BN_pseudo_rand(big, 64, 0, 0)
      BN_to_ASN1_INTEGER(big, serial)
      checkErr X509_set_serialNumber(x509, serial)
      checkErr EVP_PKEY_assign_RSA(pkey, rsa)
      rsa = nil
      checkErr X509_set_version(x509, 2)
      X509_gmtime_adj(X509_get_notBefore(x509), -60 * 60)
      X509_gmtime_adj(X509_get_notAfter(x509), 60 * 60 * 24 * 365 * 10)
      checkErr X509_set_pubkey(x509, pkey)
      var name: X509_NAME = X509_get_subject_name(x509)
      checkErr X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "JP", -1, -1, 0)
      checkErr X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Caprese Self-Signed Certificate", -1, -1, 0)
      checkErr X509_set_issuer_name(x509, name)
      checkErr X509_sign(x509, pkey, EVP_sha1())

      var retCert = SSL_CTX_use_certificate(ctx, x509)
      if retCert != 1:
        logs.error "error: self certificate"
        raise newException(ServerSslCertError, "self certificate")
      var retPriv = SSL_CTX_use_PrivateKey(ctx, pkey)
      if retPriv != 1:
        logs.error "error: self private key"
        raise newException(ServerSslCertError, "self private key")

    proc newSslCtx(site: string = "", selfSignedCertFallback: bool = false): SSL_CTX =
      var ctx = SSL_CTX_new(TLS_server_method())
      try:
        if not certsTable.isNil and site.len > 0:
          let certs = certsTable[][site]
          var retPriv = SSL_CTX_use_PrivateKey_file(ctx, cstring(certs.privPath), SSL_FILETYPE_PEM)
          if retPriv != 1:
            logs.error "error: private key file"
            raise newException(ServerSslCertError, "private key file")
          var retChain = SSL_CTX_use_certificate_chain_file(ctx, cstring(certs.chainPath))
          if retChain != 1:
            logs.error "error: chain file"
            raise newException(ServerSslCertError, "chain file")
        else:
          raise
      except:
        if not selfSignedCertFallback:
          ctx.SSL_CTX_free()
          raise
        ctx.selfSignedCertificate()

      SSL_CTX_set_options(ctx, (SSL_OP_NO_SSLv2 or SSL_OP_NO_SSLv3 or
                            SSL_OP_NO_TLSv1 or SSL_OP_NO_TLSv1_1 or SSL_OP_NO_TLSv1_2).clong)
      SSL_CTX_set_mode(ctx, (SSL_MODE_ENABLE_PARTIAL_WRITE or SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER).clong)
      result = ctx

    var sslCtx: SSL_CTX

  proc appListenBase(ctx: WorkerThreadCtx, sslFlag: static bool) {.thread, inline.} =
    let clientSock = ctx.client.sock.accept4(cast[ptr SockAddr](addr ctx.sockAddress), addr ctx.addrLen, O_NONBLOCK)
    if cast[int](clientSock) > 0:
      when cfg.soKeepalive:
        clientSock.setSockOptInt(SOL_SOCKET, SO_KEEPALIVE, 1)
      when cfg.tcpNodelay:
        clientSock.setSockOptInt(Protocol.IPPROTO_TCP.int, TCP_NODELAY, 1)
      var newClient = clientFreePool.pop()
      while newClient.isNil:
        if clientFreePool.count == 0:
          clientSock.close()
          raise
        newClient = clientFreePool.pop()
      newClient.sock = clientSock
      newClient.srvId = ctx.client.srvId
      newClient.appId = ctx.client.appId + 1

      when sslFlag and cfg.sslLib == BearSSL:
        if newClient.sc.isNil:
          newClient.sc = cast[ptr br_ssl_server_context](allocShared0(sizeof(br_ssl_server_context)))
          br_ssl_server_init_caprese(newClient.sc)
          let bidi = 1.cint
          let iobufLen = BR_SSL_BUFSIZE_BIDI.csize_t
          let iobuf = allocShared0(iobufLen)
          br_ssl_engine_set_buffer(addr newClient.sc.eng, iobuf, iobufLen, bidi)
          newClient.sendProc = sendSslProc
        if br_ssl_server_reset(newClient.sc) == 0:
          errorRaise "error: br_ssl_server_reset"

      elif sslFlag and (cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL):
        newClient.ssl = SSL_new(sslCtx)
        if SSL_set_fd(newClient.ssl, clientSock.cint) != 1:
          logs.error "error: SSL_set_fd"
          newClient.close(ssl = true)
          return
        newClient.sendProc = sendSslProc

      else:
        newClient.sendProc = sendNativeProc

      newClient.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
      let retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, cast[cint](clientSock), addr newClient.ev)
      if retCtl < 0:
        errorRaise "error: epoll_ctl ret=", retCtl, " errno=", errno

      when cfg.sslLib == None:
        if (cfg.clientMax - FreePoolServerUsedCount) - clientFreePool.count >= highGearThreshold:
          if highGearManagerAssinged == 0:
            highGear = true
            for i in 0..<serverWorkerNum:
              discard sem_post(addr throttleBody)

  proc appListen(ctx: WorkerThreadCtx) {.thread.} = appListenBase(ctx, false)

  proc appListenSsl(ctx: WorkerThreadCtx) {.thread.} = appListenBase(ctx, true)

  #[
  proc appRoutes(ctx: WorkerThreadCtx) {.thread.} =
    let client = ctx.client
    let sock = client.sock

    if client.recvCurSize == 0:
      while true:
        let recvlen = sock.recv(ctx.pRecvBuf0, workerRecvBufSize, 0.cint)
        if recvlen > 0:
          if recvlen >= 17 and equalMem(addr ctx.pRecvBuf0[recvlen - 4], "\c\L\c\L".cstring, 4):
            var nextPos = 0
            var parseSize = recvlen
            while true:
              ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[nextPos])
              let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
              if retHeader.err == 0:
                ctx.header = retHeader.header
                let retMain = mainServerHandler(ctx, client, ctx.pRecvBuf, ctx.header)
                if retMain == SendResult.Success:
                  if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                    InternalEssentialHeaderConnection) == "close":
                    client.close()
                    break
                  elif retHeader.next < recvlen:
                    nextPos = retHeader.next
                    parseSize = recvlen - nextPos
                  else:
                    break
                elif retMain == SendResult.Pending:
                  if retHeader.next < recvlen:
                    nextPos = retHeader.next
                    parseSize = recvlen - nextPos
                  else:
                    break
                else:
                  client.close()
                  break
              else:
                echo "retHeader err=", retHeader.err
                client.close()
                break

          else:
            client.addRecvBuf(ctx.pRecvBuf0, recvlen)

        elif recvlen == 0:
          client.close()

        else:
          if errno == EAGAIN or errno == EWOULDBLOCK:
            break
          elif errno == EINTR:
            continue
          client.close()
        break

    else:
      while true:
        client.reserveRecvBuf(workerRecvBufSize)
        let recvlen = sock.recv(addr client.recvBuf[client.recvCurSize], workerRecvBufSize, 0.cint)
        if recvlen > 0:
          client.recvCurSize = client.recvCurSize + recvlen
          if client.recvCurSize >= 17 and equalMem(addr client.recvBuf[client.recvCurSize - 4], "\c\L\c\L".cstring, 4):
            var nextPos = 0
            var parseSize = client.recvCurSize
            while true:
              ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[nextPos])
              let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
              if retHeader.err == 0:
                ctx.header = retHeader.header
                let retMain = mainServerHandler(ctx, client, ctx.pRecvBuf, ctx.header)
                if retMain == SendResult.Success:
                  if client.keepAlive == true:
                    if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                      InternalEssentialHeaderConnection) == "close":
                      client.keepAlive = false
                      client.close()
                      break
                    elif retHeader.next < client.recvCurSize:
                      nextPos = retHeader.next
                      parseSize = client.recvCurSize - nextPos
                    else:
                      client.recvCurSize = 0
                      break
                  else:
                    client.close()
                    break
                elif retMain == SendResult.Pending:
                  if retHeader.next < client.recvCurSize:
                    nextPos = retHeader.next
                    parseSize = client.recvCurSize - nextPos
                  else:
                    break
                else:
                  client.close()
                  break
              else:
                echo "retHeader err=", retHeader.err
                client.close()
                break

        elif recvlen == 0:
          client.close()

        else:
          if errno == EAGAIN or errno == EWOULDBLOCK:
            break
          elif errno == EINTR:
            continue
          client.close()
        break
  ]#

  proc appRoutesSend(ctx: WorkerThreadCtx) {.thread.} =
    echo "appRoutesSend"
    let client = ctx.client

    acquire(client.spinLock)
    if client.threadId == 0:
      client.threadId = ctx.threadId
      release(client.spinLock)
    else:
      client.dirty = true
      release(client.spinLock)
      return

    while true:
      client.dirty = false
      let retFlush = client.sendFlush()
      if retFlush == SendResult.Pending:
        acquire(client.spinLock)
        if not client.dirty:
          client.threadId = 0
          release(client.spinLock)
          return
        else:
          release(client.spinLock)
      elif retFlush == SendResult.Error:
        client.close()
        acquire(client.spinLock)
        client.threadId = 0
        release(client.spinLock)
        return
      else:
        acquire(client.spinLock)
        if not client.dirty:
          release(client.spinLock)
          break
        else:
          release(client.spinLock)

    let clientId = client.clientId

    var lastSendErr: SendResult
    proc taskCallback(task: ClientTask): bool =
      lastSendErr = client.send(task.data.toSeq().toString())
      result = (lastSendErr == SendResult.Success)

    while true:
      client.dirty = false
      if clientId.getAndPurgeTasks(taskCallback):
        acquire(client.spinLock)
        if not client.dirty:
          if client.appShift:
            dec(client.appId)
            client.appShift = false
          client.threadId = 0
          release(client.spinLock)

          client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
          var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
          if retCtl != 0:
            errorRaise "error: appRoutesSend epoll_ctl ret=", retCtl, " ", getErrnoStr()
          return
        else:
          release(client.spinLock)
      else:
        if lastSendErr != SendResult.Pending:
          client.close()
        acquire(client.spinLock)
        client.threadId = 0
        release(client.spinLock)

  proc appRoutesSendSsl(ctx: WorkerThreadCtx) {.thread.} =
    echo "appRoutesSendSsl"
    raise

  proc appStream(ctx: WorkerThreadCtx) {.thread.} =
    echo "appStream"

  proc appStreamSend(ctx: WorkerThreadCtx) {.thread.} =
    echo "appStreamSend"

  var clientHandlerProcs: Array[ClientHandlerProc]

  macro appDummyMacro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add appDummy

  macro appListenMacro(ssl: bool, body: untyped): untyped =
    quote do:
      when `ssl`:
        clientHandlerProcs.add appListenSsl
      else:
        clientHandlerProcs.add appListen

  template routesMainTmpl(body: untyped) {.dirty.} =
    proc routesMain(ctx: WorkerThreadCtx, client: Client): SendResult {.inline.} =
      body

  when cfg.sslLib == BearSSL:
    type
      BrEngineState = enum
        SendRec
        RecvRec
        SendApp
        RecvApp

    template brStateDebug(sc: ptr br_ssl_server_context) =
      var st = br_ssl_engine_current_state(addr sc.eng)
      var s = "state:"
      if (st and BR_SSL_CLOSED) > 0:
        s.add " BR_SSL_CLOSED"
      if (st and BR_SSL_SENDREC) > 0:
        s.add " BR_SSL_SENDREC"
      if (st and BR_SSL_RECVREC) > 0:
        s.add " BR_SSL_RECVREC"
      if (st and BR_SSL_SENDAPP) > 0:
        s.add " BR_SSL_SENDAPP"
      if (st and BR_SSL_RECVAPP) > 0:
        s.add " BR_SSL_RECVAPP"
      echo s

  macro appRoutesMacro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add proc (ctx: WorkerThreadCtx) {.thread.} =
        when `ssl`:
          let client = ctx.client
          let sock = client.sock

          acquire(client.spinLock)
          if client.threadId == 0:
            client.threadId = ctx.threadId
            release(client.spinLock)
          else:
            client.dirty = true
            release(client.spinLock)
            return

          routesMainTmpl(`body`)

          when cfg.sslLib == BearSSL:
            let sc = client.sc
            let ec = addr client.sc.eng
            var bufLen: csize_t
            var buf: ptr UncheckedArray[byte]

            var engine = RecvApp

            block engineBlock:
              while true:
                {.computedGoto.}
                case engine
                of RecvApp:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvapp_buf(ec, addr bufLen))
                  if buf.isNil:
                    engine = SendRec
                  else:
                    client.addRecvBuf(buf, bufLen.int, if bufLen.int > workerRecvBufSize: bufLen.int else: workerRecvBufSize)
                    br_ssl_engine_recvapp_ack(ec, bufLen.csize_t)

                    if client.recvCurSize >= 17 and equalMem(addr client.recvBuf[client.recvCurSize - 4], "\c\L\c\L".cstring, 4):
                      var nextPos = 0
                      var parseSize = client.recvCurSize
                      while true:
                        ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[nextPos])
                        let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
                        if retHeader.err == 0:
                          ctx.header = retHeader.header
                          let retMain = routesMain(ctx, client)
                          engine = SendRec
                          if retMain == SendResult.Success:
                            if client.keepAlive == true:
                              if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                                InternalEssentialHeaderConnection) == "close":
                                client.keepAlive = false
                                client.close()
                                break engineBlock
                              elif retHeader.next < client.recvCurSize:
                                nextPos = retHeader.next
                                parseSize = client.recvCurSize - nextPos
                              else:
                                client.recvCurSize = 0
                                acquire(client.spinLock)
                                if client.dirty:
                                  client.dirty = false
                                  release(client.spinLock)
                                  engine = RecvApp
                                  break
                                else:
                                  client.threadId = 0
                                  release(client.spinLock)
                                  break engineBlock
                            else:
                              client.close()
                              break engineBlock
                          elif retMain == SendResult.Pending:
                            if retHeader.next < parseSize:
                              nextPos = retHeader.next
                              parseSize = parseSize - nextPos
                            else:
                              client.recvCurSize = 0
                              engine = SendApp
                              break
                          else:
                            client.close()
                            break engineBlock
                        else:
                          client.close()
                          break engineBlock

                of SendRec:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendrec_buf(ec, addr bufLen))
                  if buf.isNil:
                    engine = RecvRec
                    if client.ev.events == (EPOLLIN or EPOLLRDHUP or EPOLLET or EPOLLOUT):
                      client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                      if retCtl != 0:
                        acquire(client.spinLock)
                        client.threadId = 0
                        release(client.spinLock)
                        break
                  else:
                    let sendlen = sock.send(buf, bufLen.int, 0.cint)
                    if sendlen > 0:
                      br_ssl_engine_sendrec_ack(ec, sendlen.csize_t)
                      if client.sendCurSize > 0:
                        engine = SendApp
                      else:
                        engine = RecvApp
                    elif sendlen == 0:
                      client.close()
                      break
                    else:
                      if errno == EAGAIN or errno == EWOULDBLOCK:
                        client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET or EPOLLOUT
                        var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                        if retCtl != 0:
                          acquire(client.spinLock)
                          client.threadId = 0
                          release(client.spinLock)
                          break
                        acquire(client.spinLock)
                        if client.dirty:
                          client.dirty = false
                          release(client.spinLock)
                          if client.sendCurSize > 0:
                            engine = SendApp
                          else:
                            engine = RecvApp
                        else:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                      elif errno == EINTR:
                        continue
                      else:
                        client.close()
                        break

                of RecvRec:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvrec_buf(ec, addr bufLen))
                  if buf.isNil:
                    engine = SendApp
                  else:
                    let recvlen = sock.recv(buf, bufLen.int, 0.cint)
                    if recvlen > 0:
                      br_ssl_engine_recvrec_ack(ec, recvlen.csize_t)
                      engine = RecvApp
                    elif recvlen == 0:
                      client.close()
                      break
                    else:
                      if errno == EAGAIN or errno == EWOULDBLOCK:
                        acquire(client.spinLock)
                        if client.dirty:
                          client.dirty = false
                          release(client.spinLock)
                          engine = RecvApp
                        else:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                      elif errno == EINTR:
                        continue
                      else:
                        client.close()
                        break

                of SendApp:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendapp_buf(ec, addr bufLen))
                  if buf.isNil:
                    acquire(client.spinLock)
                    if client.dirty:
                      client.dirty = false
                      release(client.spinLock)
                      engine = RecvApp
                    else:
                      client.threadId = 0
                      release(client.spinLock)
                      break
                  else:
                    var sendSize = client.sendCurSize
                    acquire(client.lock)
                    if client.sendCurSize > 0:
                      if bufLen.int >= client.sendCurSize:
                        copyMem(buf, addr client.sendBuf[0], client.sendCurSize)
                        client.sendCurSize = 0
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, sendSize.csize_t)
                        br_ssl_engine_flush(ec, 0)
                      else:
                        copyMem(buf, client.sendBuf, bufLen.int)
                        client.sendCurSize = client.sendCurSize - bufLen.int
                        copyMem(addr client.sendBuf[0], addr client.sendBuf[bufLen], client.sendCurSize)
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, bufLen)
                        br_ssl_engine_flush(ec, 0)
                    else:
                      release(client.lock)
                    engine = SendRec

          elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
            while true:
              ERR_clear_error()
              let retSslAccept = SSL_accept(client.ssl)
              if retSslAccept < 0:
                client.sslErr = SSL_get_error(client.ssl, retSslAccept)
                debug "SSL_accept err=", client.sslErr, " errno=", errno
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    break
                  else:
                    client.dirty = false
                    release(client.spinLock)
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  acquire(client.spinLock)
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    break
                  else:
                    client.dirty = false
                    release(client.spinLock)
                else:
                  if errno == EINTR:
                    continue
                  client.close(ssl = true)
                  break
              elif retSslAccept == 0:
                client.close(ssl = true)
                break
              else:
                inc(client.appId)
                acquire(client.spinLock)
                client.threadId = 0
                release(client.spinLock)
                client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET or EPOLLOUT
                var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                if retCtl != 0:
                  logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                break

        else:
          let client = ctx.client
          let sock = client.sock

          routesMainTmpl(`body`)

          if client.recvCurSize == 0:
            while true:
              let recvlen = sock.recv(ctx.pRecvBuf0, workerRecvBufSize, 0.cint)
              if recvlen > 0:
                if recvlen >= 17 and equalMem(addr ctx.pRecvBuf0[recvlen - 4], "\c\L\c\L".cstring, 4):
                  var nextPos = 0
                  var parseSize = recvlen
                  while true:
                    ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[nextPos])
                    let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
                    if retHeader.err == 0:
                      ctx.header = retHeader.header
                      let retMain = routesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                          InternalEssentialHeaderConnection) == "close":
                          client.close()
                          break
                        elif retHeader.next < recvlen:
                          nextPos = retHeader.next
                          parseSize = recvlen - nextPos
                        else:
                          break
                      elif retMain == SendResult.Pending:
                        if retHeader.next < recvlen:
                          nextPos = retHeader.next
                          parseSize = recvlen - nextPos
                        else:
                          break
                      else:
                        client.close()
                        break
                    else:
                      echo "retHeader err=", retHeader.err
                      client.close()
                      break

                else:
                  client.addRecvBuf(ctx.pRecvBuf0, recvlen)

              elif recvlen == 0:
                client.close()

              else:
                if errno == EAGAIN or errno == EWOULDBLOCK:
                  break
                elif errno == EINTR:
                  continue
                client.close()
              break

          else:
            while true:
              client.reserveRecvBuf(workerRecvBufSize)
              let recvlen = sock.recv(addr client.recvBuf[client.recvCurSize], workerRecvBufSize, 0.cint)
              if recvlen > 0:
                client.recvCurSize = client.recvCurSize + recvlen
                if client.recvCurSize >= 17 and equalMem(addr client.recvBuf[client.recvCurSize - 4], "\c\L\c\L".cstring, 4):
                  var nextPos = 0
                  var parseSize = client.recvCurSize
                  while true:
                    ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[nextPos])
                    let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
                    if retHeader.err == 0:
                      ctx.header = retHeader.header
                      let retMain = routesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if client.keepAlive == true:
                          if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                            InternalEssentialHeaderConnection) == "close":
                            client.keepAlive = false
                            client.close()
                            break
                          elif retHeader.next < parseSize:
                            nextPos = retHeader.next
                            parseSize = parseSize - nextPos
                          else:
                            client.recvCurSize = 0
                            break
                        else:
                          client.close()
                          break
                      elif retMain == SendResult.Pending:
                        if retHeader.next < parseSize:
                          nextPos = retHeader.next
                          parseSize = parseSize - nextPos
                        else:
                          client.recvCurSize = 0
                          break
                      else:
                        client.close()
                        break
                    else:
                      echo "retHeader err=", retHeader.err
                      client.close()
                      break

              elif recvlen == 0:
                client.close()

              else:
                if errno == EAGAIN or errno == EWOULDBLOCK:
                  break
                elif errno == EINTR:
                  continue
                client.close()
              break

  macro appRoutesStage1Macro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add proc (ctx: WorkerThreadCtx) {.thread.} =
        let client = ctx.client
        let sock = client.sock

        acquire(client.spinLock)
        if client.threadId == 0:
          client.threadId = ctx.threadId
          release(client.spinLock)
        else:
          client.dirty = true
          release(client.spinLock)
          return

        routesMainTmpl(`body`)

        when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
          if client.recvCurSize == 0:
            while true:
              client.dirty = false
              let recvlen = client.ssl.SSL_read(cast[pointer](ctx.pRecvBuf0), workerRecvBufSize.cint).int
              if recvlen > 0:
                if recvlen >= 17 and equalMem(addr ctx.pRecvBuf0[recvlen - 4], "\c\L\c\L".cstring, 4):
                  var nextPos = 0
                  var parseSize = recvlen
                  while true:
                    ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[nextPos])
                    let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
                    if retHeader.err == 0:
                      ctx.header = retHeader.header
                      let retMain = routesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                          InternalEssentialHeaderConnection) == "close":
                          client.close(ssl = true)
                          break
                        elif retHeader.next < recvlen:
                          nextPos = retHeader.next
                          parseSize = recvlen - nextPos
                        else:
                          break
                      elif retMain == SendResult.Pending:
                        if retHeader.next < recvlen:
                          nextPos = retHeader.next
                          parseSize = recvlen - nextPos
                        else:
                          break
                      else:
                        client.close(ssl = true)
                        break
                    else:
                      client.close(ssl = true)
                      break
                else:
                  client.addRecvBuf(ctx.pRecvBuf0, recvlen)

              elif recvlen == 0:
                client.close(ssl = true)

              else:
                client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                else:
                  if errno == EINTR:
                    continue
                  client.close(ssl = true)
                  break

          else:
            while true:
              client.reserveRecvBuf(workerRecvBufSize)
              let recvlen = client.ssl.SSL_read(cast[pointer](addr client.recvBuf[client.recvCurSize]), workerRecvBufSize.cint).int
              if recvlen > 0:
                client.recvCurSize = client.recvCurSize + recvlen
                if client.recvCurSize >= 17 and equalMem(addr client.recvBuf[client.recvCurSize - 4], "\c\L\c\L".cstring, 4):
                  var nextPos = 0
                  var parseSize = client.recvCurSize
                  while true:
                    ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[nextPos])
                    let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders)
                    if retHeader.err == 0:
                      ctx.header = retHeader.header
                      let retMain = routesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if client.keepAlive == true:
                          if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                            InternalEssentialHeaderConnection) == "close":
                            client.keepAlive = false
                            client.close(ssl = true)
                            break
                          elif retHeader.next < parseSize:
                            nextPos = retHeader.next
                            parseSize = parseSize - nextPos
                          else:
                            client.recvCurSize = 0
                            break
                        else:
                          client.close(ssl = true)
                          break
                      elif retMain == SendResult.Pending:
                        if retHeader.next < parseSize:
                          nextPos = retHeader.next
                          parseSize = parseSize - nextPos
                        else:
                          client.recvCurSize = 0
                          break
                      else:
                        client.close(ssl = true)
                        break
                    else:
                      client.close(ssl = true)
                      break

              elif recvlen == 0:
                client.close(ssl = true)

              else:
                if errno == EAGAIN or errno == EWOULDBLOCK:
                  break
                elif errno == EINTR:
                  continue
                client.close(ssl = true)
              break

        else:
          raise

        acquire(client.spinLock)
        client.threadId = 0
        release(client.spinLock)

  macro appRoutesStage2Macro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add proc (ctx: WorkerThreadCtx) {.thread.} =
        when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
          let client = ctx.client

          acquire(client.spinLock)
          if client.threadId == 0:
            client.threadId = ctx.threadId
            release(client.spinLock)
          else:
            client.dirty = true
            release(client.spinLock)
            return

          while true:
            client.dirty = false
            let retFlush = client.sendSslFlush()
            if retFlush == SendResult.Pending:
              acquire(client.spinLock)
              if not client.dirty:
                client.threadId = 0
                release(client.spinLock)
                return
              else:
                release(client.spinLock)
            elif retFlush == SendResult.Error:
              client.close()
              acquire(client.spinLock)
              client.threadId = 0
              release(client.spinLock)
              return
            else:
              acquire(client.spinLock)
              if not client.dirty:
                release(client.spinLock)
                break
              else:
                release(client.spinLock)

          let clientId = client.clientId

          var lastSendErr: SendResult
          proc taskCallback(task: ClientTask): bool =
            lastSendErr = client.send(task.data.toSeq().toString())
            result = (lastSendErr == SendResult.Success)

          while true:
            client.dirty = false
            if clientId.getAndPurgeTasks(taskCallback):
              acquire(client.spinLock)
              if not client.dirty:
                if client.appShift:
                  dec(client.appId)
                  client.appShift = false
                client.threadId = 0
                release(client.spinLock)

                client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                if retCtl != 0:
                  errorRaise "error: appRoutesSend epoll_ctl ret=", retCtl, " ", getErrnoStr()
                return
              else:
                release(client.spinLock)
            else:
              if lastSendErr != SendResult.Pending:
                client.close()
              acquire(client.spinLock)
              client.threadId = 0
              release(client.spinLock)

              let client = ctx.client
              let sock = client.sock

              acquire(client.spinLock)
              if client.threadId == 0:
                client.threadId = ctx.threadId
                release(client.spinLock)
              else:
                client.dirty = true
                release(client.spinLock)
                return
        else:
          raise

  macro appRoutesSendMacro(ssl: bool, body: untyped): untyped =
    quote do:
      when `ssl`:
        clientHandlerProcs.add appRoutesSendSsl
      else:
        clientHandlerProcs.add appRoutesSend

  template streamMainTmpl(body: untyped) {.dirty.} =
    proc streamMain(client: Client, opcode: WebSocketOpCode,
      data: ptr UncheckedArray[byte], size: int): SendResult =
      body

  template streamMainTmpl(messageBody: untyped, closeBody: untyped) {.dirty.} =
    proc streamMain(client: Client, opcode: WebSocketOpCode,
      data: ptr UncheckedArray[byte], size: int): SendResult =
      case opcode
      of WebSocketOpcode.Binary, WebSocketOpcode.Text, WebSocketOpcode.Continue:
        messageBody
      of WebSocketOpcode.Ping:
        return client.wsServerSend(data.toString(size), WebSocketOpcode.Pong)
      of WebSocketOpcode.Pong:
        debug "pong ", data.toString(size)
        return SendResult.Success
      else: # WebSocketOpcode.Close
        closeBody
        return SendResult.None

  template onProtocol(body: untyped) = discard
  template onOpen(body: untyped) = discard
  template onMessage(body: untyped) = discard
  template onClose(body: untyped) = discard

  macro appStreamMacro(ssl: bool, body: untyped): untyped =
    var onMessageStmt = newStmtList()
    var onCloseStmt = newStmtList()
    var rawStmt = newStmtList()

    for s in body:
      if eqIdent(s[0], "onProtocol"):
        continue
      elif eqIdent(s[0], "onOpen"):
        continue
      elif eqIdent(s[0], "onMessage"):
        onMessageStmt.add(s[1])
      elif eqIdent(s[0], "onClose"):
        onCloseStmt.add(s[1])
      else:
        rawStmt.add(s)

    var callStreamMainTmplStmt: NimNode
    if onMessageStmt.len > 0 or onCloseStmt.len > 0:
      if onMessageStmt.len  == 0:
        onMessageStmt.add quote do:
          return SendResult.Pending
      callStreamMainTmplStmt = quote do:
        streamMainTmpl(`onMessageStmt`, `onCloseStmt`)
    else:
      callStreamMainTmplStmt = quote do:
        streamMainTmpl(`rawStmt`)

    quote do:
      clientHandlerProcs.add proc (ctx: WorkerThreadCtx) {.thread.} =
        when `ssl`:
          when cfg.sslLib == BearSSL:
            echo "stream bearssl"
            let client = ctx.client
            let sock = client.sock

            acquire(client.spinLock)
            if client.threadId == 0:
              client.threadId = ctx.threadId
              release(client.spinLock)
            else:
              client.dirty = true
              release(client.spinLock)
              return

            `callStreamMainTmplStmt`

            let sc = client.sc
            let ec = addr client.sc.eng
            var bufLen: csize_t
            var buf: ptr UncheckedArray[byte]

            var engine = if client.sendCurSize > 0: SendApp else: RecvApp

            block engineBlock:
              while true:
                {.computedGoto.}
                case engine
                of RecvApp:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvapp_buf(ec, addr bufLen))
                  if buf.isNil:
                    engine = SendRec
                  else:
                    if client.recvCurSize == 0:
                      client.payloadSize = 0
                    client.addRecvBuf(buf, bufLen.int, if bufLen.int > workerRecvBufSize: bufLen.int else: workerRecvBufSize)
                    br_ssl_engine_recvapp_ack(ec, bufLen.csize_t)
                    var p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
                    var (find, fin, opcode, payload, payloadSize,
                        next, size) = getFrame(p, client.recvCurSize - client.payloadSize)
                    while find:
                      if not payload.isNil and payloadSize > 0:
                        copyMem(p, payload, payloadSize)
                        client.payloadSize = client.payloadSize + payloadSize
                        p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
                      if fin:
                        var retStream = client.streamMain(opcode.toWebSocketOpCode,
                                                          cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]),
                                                          client.payloadSize)
                        case retStream
                        of SendResult.Success, SendResult.Pending:
                          engine = SendApp
                        of SendResult.None, SendResult.Error, SendResult.Invalid:
                          client.close()
                          break engineBlock
                        client.payloadSize = 0
                      (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

                    if not next.isNil and size > 0:
                      copyMem(p, next, size)
                      client.recvCurSize = client.payloadSize + size
                    else:
                      client.recvCurSize = client.payloadSize

                of SendRec:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendrec_buf(ec, addr bufLen))
                  if buf.isNil:
                    engine = RecvRec
                    if client.ev.events == (EPOLLIN or EPOLLRDHUP or EPOLLET or EPOLLOUT):
                      client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                      if retCtl != 0:
                        acquire(client.spinLock)
                        client.threadId = 0
                        release(client.spinLock)
                        break
                  else:
                    let sendlen = sock.send(buf, bufLen.int, 0.cint)
                    if sendlen > 0:
                      br_ssl_engine_sendrec_ack(ec, sendlen.csize_t)
                      if client.sendCurSize > 0:
                        engine = SendApp
                      else:
                        engine = RecvApp
                    elif sendlen == 0:
                      client.close()
                      break
                    else:
                      if errno == EAGAIN or errno == EWOULDBLOCK:
                        client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET or EPOLLOUT
                        var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                        if retCtl != 0:
                          acquire(client.spinLock)
                          client.threadId = 0
                          release(client.spinLock)
                          break
                        acquire(client.spinLock)
                        if client.dirty:
                          client.dirty = false
                          release(client.spinLock)
                          if client.sendCurSize > 0:
                            engine = SendApp
                          else:
                            engine = RecvApp
                        else:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                      elif errno == EINTR:
                        continue
                      else:
                        client.close()
                        break

                of RecvRec:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvrec_buf(ec, addr bufLen))
                  if buf.isNil:
                    engine = SendApp
                  else:
                    let recvlen = sock.recv(buf, bufLen.int, 0.cint)
                    if recvlen > 0:
                      br_ssl_engine_recvrec_ack(ec, recvlen.csize_t)
                      engine = RecvApp
                    elif recvlen == 0:
                      client.close()
                      break
                    else:
                      if errno == EAGAIN or errno == EWOULDBLOCK:
                        acquire(client.spinLock)
                        if client.dirty:
                          client.dirty = false
                          release(client.spinLock)
                          engine = RecvApp
                        else:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                      elif errno == EINTR:
                        continue
                      else:
                        client.close()
                        break

                of SendApp:
                  buf = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendapp_buf(ec, addr bufLen))
                  if buf.isNil:
                    acquire(client.spinLock)
                    if client.dirty:
                      client.dirty = false
                      release(client.spinLock)
                      engine = RecvApp
                    else:
                      client.threadId = 0
                      release(client.spinLock)
                      break
                  else:
                    var sendSize = client.sendCurSize
                    acquire(client.lock)
                    if client.sendCurSize > 0:
                      if bufLen.int >= client.sendCurSize:
                        copyMem(buf, addr client.sendBuf[0], client.sendCurSize)
                        client.sendCurSize = 0
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, sendSize.csize_t)
                        br_ssl_engine_flush(ec, 0)
                      else:
                        copyMem(buf, client.sendBuf, bufLen.int)
                        client.sendCurSize = client.sendCurSize - bufLen.int
                        copyMem(addr client.sendBuf[0], addr client.sendBuf[bufLen], client.sendCurSize)
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, bufLen)
                        br_ssl_engine_flush(ec, 0)
                    else:
                      release(client.lock)
                    engine = SendRec

          elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
            echo "stream openssl"
            let client = ctx.client

            acquire(client.spinLock)
            if client.threadId == 0:
              client.threadId = ctx.threadId
              release(client.spinLock)
            else:
              client.dirty = true
              release(client.spinLock)
              return

            let sock = client.sock

            `callStreamMainTmplStmt`

            if client.recvCurSize == 0:
              while true:
                client.dirty = false
                let recvlen = client.ssl.SSL_read(cast[pointer](ctx.pRecvBuf0), workerRecvBufSize.cint).int
                if recvlen > 0:
                  var (find, fin, opcode, payload, payloadSize,
                      next, size) = getFrame(ctx.pRecvBuf0, recvlen)
                  while find:
                    if fin:
                      var retStream = client.streamMain(opcode.toWebSocketOpCode, payload, payloadSize)
                      case retStream
                      of SendResult.Success:
                        discard
                      of SendResult.Pending:
                        discard
                      of SendResult.None, SendResult.Error, SendResult.Invalid:
                        client.close(ssl = true)
                    else:
                      if not payload.isNil and payloadSize > 0:
                        client.addRecvBuf(payload, payloadSize)
                        client.payloadSize = payloadSize
                      break
                    (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

                  if not next.isNil and size > 0:
                    client.addRecvBuf(next, size)
                    if recvlen == workerRecvBufSize:
                      break

                  acquire(client.spinLock)
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    return
                  else:
                    release(client.spinLock)
                    break

                elif recvlen == 0:
                  client.close(ssl = true)
                  acquire(client.spinLock)
                  client.threadId = 0
                  release(client.spinLock)
                  return
                else:
                  client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                  if client.sslErr == SSL_ERROR_WANT_READ:
                    acquire(client.spinLock)
                    if not client.dirty:
                      client.threadId = 0
                      release(client.spinLock)
                      client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                      if retCtl != 0:
                        logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                      return
                    else:
                      release(client.spinLock)
                  elif client.sslErr == SSL_ERROR_WANT_WRITE:
                    if not client.dirty:
                      client.threadId = 0
                      release(client.spinLock)
                      client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                      if retCtl != 0:
                        logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                      return
                    else:
                      release(client.spinLock)
                  else:
                    if errno == EINTR:
                      continue
                    client.close(ssl = true)
                    break

            while true:
              client.reserveRecvBuf(workerRecvBufSize)
              client.dirty = false
              var recvlen = client.ssl.SSL_read(cast[pointer](addr client.recvBuf[client.recvCurSize]), workerRecvBufSize.cint).int
              if recvlen > 0:
                client.recvCurSize = client.recvCurSize + recvlen
                var p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
                var (find, fin, opcode, payload, payloadSize,
                    next, size) = getFrame(p, client.recvCurSize - client.payloadSize)
                while find:
                  if not payload.isNil and payloadSize > 0:
                    copyMem(p, payload, payloadSize)
                    client.payloadSize = client.payloadSize + payloadSize
                    p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
                  if fin:
                    var retStream = client.streamMain(opcode.toWebSocketOpCode,
                                                      cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]),
                                                      client.payloadSize)
                    case retStream
                    of SendResult.Success:
                      discard
                    of SendResult.Pending:
                      discard
                    of SendResult.None, SendResult.Error, SendResult.Invalid:
                      client.close(ssl = true)
                    client.payloadSize = 0
                    client.recvCurSize = 0
                  (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

                if not next.isNil and size > 0:
                  copyMem(p, next, size)
                  client.recvCurSize = client.payloadSize + size
                  if recvlen == workerRecvBufSize:
                    continue
                else:
                  client.recvCurSize = client.payloadSize
              elif recvlen == 0:
                client.close(ssl = true)
                break
              else:
                client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                else:
                  if errno == EINTR:
                    continue
                  client.close(ssl = true)
                  break

            acquire(client.spinLock)
            client.threadId = 0
            release(client.spinLock)

        else:
          let client = ctx.client

          acquire(client.spinLock)
          if client.threadId == 0:
            client.threadId = ctx.threadId
            release(client.spinLock)
          else:
            client.dirty = true
            release(client.spinLock)
            return

          let sock = client.sock

          `callStreamMainTmplStmt`

          if client.recvCurSize == 0:
            while true:
              client.dirty = false
              let recvlen = sock.recv(ctx.pRecvBuf0, workerRecvBufSize, 0.cint)
              if recvlen > 0:
                var (find, fin, opcode, payload, payloadSize,
                    next, size) = getFrame(ctx.pRecvBuf0, recvlen)
                while find:
                  if fin:
                    var retStream = client.streamMain(opcode.toWebSocketOpCode, payload, payloadSize)
                    case retStream
                    of SendResult.Success:
                      discard
                    of SendResult.Pending:
                      discard
                    of SendResult.None, SendResult.Error, SendResult.Invalid:
                      client.close()
                  else:
                    if not payload.isNil and payloadSize > 0:
                      client.addRecvBuf(payload, payloadSize)
                      client.payloadSize = payloadSize
                    break
                  (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

                if not next.isNil and size > 0:
                  client.addRecvBuf(next, size)
                  if recvlen == workerRecvBufSize:
                    break

                acquire(client.spinLock)
                if not client.dirty:
                  client.threadId = 0
                  release(client.spinLock)
                  return
                else:
                  release(client.spinLock)
                  break

              elif recvlen == 0:
                client.close()
                acquire(client.spinLock)
                client.threadId = 0
                release(client.spinLock)
                return
              else:
                if errno == EAGAIN or errno == EWOULDBLOCK:
                  acquire(client.spinLock)
                  if not client.dirty:
                    client.threadId = 0
                    release(client.spinLock)
                    return
                  else:
                    release(client.spinLock)
                    break
                elif errno == EINTR:
                  continue
                client.close()
                acquire(client.spinLock)
                client.threadId = 0
                release(client.spinLock)
                return

          while true:
            client.reserveRecvBuf(workerRecvBufSize)
            client.dirty = false
            var recvlen = sock.recv(addr client.recvBuf[client.recvCurSize], workerRecvBufSize.cint, 0.cint)
            if recvlen > 0:
              client.recvCurSize = client.recvCurSize + recvlen
              var p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
              var (find, fin, opcode, payload, payloadSize,
                  next, size) = getFrame(p, client.recvCurSize - client.payloadSize)
              while find:
                if not payload.isNil and payloadSize > 0:
                  copyMem(p, payload, payloadSize)
                  client.payloadSize = client.payloadSize + payloadSize
                  p = cast[ptr UncheckedArray[byte]](addr client.recvBuf[client.payloadSize])
                if fin:
                  var retStream = client.streamMain(opcode.toWebSocketOpCode,
                                                    cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]),
                                                    client.payloadSize)
                  case retStream
                  of SendResult.Success:
                    discard
                  of SendResult.Pending:
                    discard
                  of SendResult.None, SendResult.Error, SendResult.Invalid:
                    client.close()
                  client.payloadSize = 0
                  client.recvCurSize = 0
                (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

              if not next.isNil and size > 0:
                copyMem(p, next, size)
                client.recvCurSize = client.payloadSize + size
                if recvlen == workerRecvBufSize:
                  continue
              else:
                client.recvCurSize = client.payloadSize
            elif recvlen == 0:
              client.close()
              break
            else:
              if errno == EAGAIN or errno == EWOULDBLOCK:
                acquire(client.spinLock)
                if not client.dirty:
                  release(client.spinLock)
                  break
                else:
                  release(client.spinLock)
                  continue
              elif errno == EINTR:
                continue
              client.close()
              break

          acquire(client.spinLock)
          client.threadId = 0
          release(client.spinLock)

  macro appStreamSendMacro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add appRoutesSend # appStreamSend is same

  proc addHandlerProc(name: string, ssl: NimNode, body: NimNode): NimNode {.compileTime.} =
    newCall(name & "Macro", ssl, body)

  macro serverHandlerMacro(): untyped =
    result = newStmtList()
    for s in serverHandlerList:
      result.add(addHandlerProc(s[0], s[1], s[2]))

  serverHandlerMacro()

  createCertsTable()
  certsTable = unsafeAddr staticCertsTable
  certsIdxTable = unsafeAddr staticCertsIdxTable
  for c in certsTable[].pairs:
    addCertsList(c[0], c[1].idx)

  createCertsFileNameList()

  when cfg.sslLib == BearSSL:
    certKeyChainsList.setLen(staticCertsTable.len + 1)

  when cfg.sslLib != None:
    import std/inotify

    var inoty: FileHandle = inotify_init()
    if inoty == -1:
      errorQuit "error: inotify_init err=", errno

    when cfg.sslLib == BearSSL:
      when defined(BEARSSL_DEFAULT_EC):
        certKeyChainsList[0].key = CertPrivateKey(
          type: CertPrivateKeyType.EC,
          ec: cast[ptr br_ec_private_key](unsafeAddr EC))
      else:
        certKeyChainsList[0].key = CertPrivateKey(
          type: CertPrivateKeyType.RSA,
          rsa: cast[ptr br_rsa_private_key](unsafeAddr RSA))
      certKeyChainsList[0].chains = X509CertificateChains(
        cert: cast[ptr UncheckedArray[br_x509_certificate]](unsafeAddr CHAIN[0]),
        certLen: CHAIN_LEN.csize_t)
      for serverName, val in certsTable[].pairs:
        let certKeyChains = addr certKeyChainsList[val.idx]
        let certsPath = certsTable[][serverName]
        var noFile = false
        if not fileExists(certsPath.privPath):
          logs.error "not found ", certsPath.privPath
          noFile = true
        if not fileExists(certsPath.chainPath):
          logs.error "not found ", certsPath.chainPath
          noFile = true
        if noFile:
          continue
        try:
          certKeyChains[].chains = createChains(readFile(certsPath.chainPath))
          try:
            var certDatas = decodePem(readFile(certsPath.privPath))
            let certData = certDatas[0]
            certKeyChains[].key = decodeCertPrivateKey(certData.data)
            clearPemObjs(certDatas)
          except:
            freeChains(certKeyChainsList[val.idx].chains)
            let e = getCurrentException()
            logs.error e.name, " ", e.msg
        except:
          let e = getCurrentException()
          logs.error e.name, " ", e.msg

    when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
      type
        SiteCtx = object
          ctx: SSL_CTX

      var siteCtxs: array[staticCertsTable.len + 1, SiteCtx]
      for site in certsTable[].keys:
        var val = certsTable[][site]
        siteCtxs[val.idx].ctx = newSslCtx(selfSignedCertFallback = true)

    var certUpdateFlags: array[staticCertsTable.len + 1, tuple[priv, chain: bool, checkCount: int]]
    for i in 0..<certUpdateFlags.len:
      certUpdateFlags[i] = (false, false, 0)

    var folderCheck = true
    var checkFolders: seq[string]
    for c in certsTable[].values:
      for _, path in [c.privPath, c.chainPath]:
        let folder = splitPath(path).head
        if not (folder in checkFolders):
          checkFolders.add(folder)
    for folder in checkFolders:
      if not dirExists(folder):
        logs.error "error: not found path=", folder
        folderCheck = false
    if not folderCheck:
      logs.error "error: certificates path does not exists"

    var certWatchList: Array[tuple[path: Array[char], wd: cint, idxList: Array[tuple[idx: int, ctype: int]]]]
    var idx = 1
    for c in certsTable[].values:
      for ctype, path in [c.privPath, c.chainPath]:
        block SearchPath:
          let watchFolder = splitPath(path).head
          for i, w in certWatchList:
            if w.path.toString == watchFolder:
              certWatchList[i].idxList.add((idx, ctype.int))
              break SearchPath
          var wd = inotify_add_watch(inoty, watchFolder.cstring, IN_CLOSE_WRITE)
          if wd == -1:
            logs.error "error: inotify_add_watch path=", watchFolder
          var nextPos = certWatchList.len
          certWatchList.setLen(nextPos + 1)
          certWatchList[nextPos].path = watchFolder.toArray
          certWatchList[nextPos].wd = wd
          certWatchList[nextPos].idxList.add((idx, ctype.int))
      inc(idx)

    proc freeFileWatcher() =
      if inoty != -1:
        for w in certWatchList:
          if w.wd >= 0:
            discard inoty.inotify_rm_watch(w.wd)
        discard inoty.close()
        inoty = -1

    proc fileWatcher(arg: ThreadArg) {.thread.} =
      var evs = newSeq[byte](sizeof(InotifyEvent) * 512)
      var fds: array[1, TPollfd]
      fds[0].events = POLLIN
      var sec = 0

      template updateCerts(idx: int) =
        certUpdateFlags[idx] = (false, false, 0)

        when cfg.sslLib == BearSSL:
          for site, val in certsTable[].pairs:
            if val.idx == idx:
              var noFile = false
              if not fileExists(val.privPath):
                logs.debug "not found ", val.privPath
                noFile = true
              if not fileExists(val.chainPath):
                logs.debug "not found ", val.chainPath
                noFile = true
              let certKeyChains = addr certKeyChainsList[idx]
              if certKeyChains[].key.type != CertPrivateKeyType.None:
                acquire(certKeyChainsListLock)
                freeCertPrivateKey(certKeyChainsList[idx].key)
                freeChains(certKeyChainsList[idx].chains)
              else:
                acquire(certKeyChainsListLock)
              if noFile:
                release(certKeyChainsListLock)
                break
              try:
                certKeyChains[].chains = createChains(readFile(val.chainPath))
                try:
                  var certDatas = decodePem(readFile(val.privPath))
                  let certData = certDatas[0]
                  certKeyChains[].key = decodeCertPrivateKey(certData.data)
                  clearPemObjs(certDatas)
                  release(certKeyChainsListLock)
                except:
                  freeChains(certKeyChainsList[idx].chains)
                  release(certKeyChainsListLock)
                  let e = getCurrentException()
                  logs.error e.name, " ", e.msg
              except:
                release(certKeyChainsListLock)
                let e = getCurrentException()
                logs.error e.name, " ", e.msg
              break

        when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
          for site, val in certsTable[].pairs:
            if val.idx == idx:
              var oldCtx = siteCtxs[idx].ctx
              siteCtxs[idx].ctx = newSslCtx(selfSignedCertFallback = true)
              oldCtx.SSL_CTX_free()
              break

      while active:
        if inoty == -1:
          sleep(3000)
        else:
          fds[0].fd = inoty
          var pollNum = poll(addr fds[0], 1, 3000)
          if pollNum <= 0:
            if errno == EINTR: continue
            inc(sec, 3)
            if sec >= 30:
              sec = 0
              for idx, flag in certUpdateFlags:
                if flag.priv or flag.chain:
                  if certUpdateFlags[idx].checkCount > 0:
                    updateCerts(idx)
                  else:
                    inc(certUpdateFlags[idx].checkCount)
              for i, w in certWatchList:
                if w.wd == -1:
                  let watchFolder = w.path.toString()
                  certWatchList[i].wd = inotify_add_watch(inoty, watchFolder.cstring, IN_CLOSE_WRITE)
                  if certWatchList[i].wd >= 0:
                    logs.debug "certs watch add: ", watchFolder
                    for d in w.idxList:
                      var idx = d.idx
                      updateCerts(idx)
            continue
          let n = read(inoty, evs[0].addr, evs.len)
          if n <= 0: break
          for e in inotify_events(evs[0].addr, n):
            if e[].len > 0:
              for i, w in certWatchList:
                if w.wd == e[].wd:
                  var ids = w.idxList
                  var filename = $cast[cstring](addr e[].name)
                  logs.debug "certs watch: ", w.path.toString / filename
                  for d in ids:
                    case d.ctype
                    of 0:
                      if filename == certsFileNameList[d.idx].privFileName:
                        certUpdateFlags[d.idx].priv = true
                    of 1:
                      if filename == certsFileNameList[d.idx].chainFileName:
                        certUpdateFlags[d.idx].chain = true
                    else: discard
                  break
            else:
              for i, w in certWatchList:
                if w.wd == e[].wd:
                  if (e[].mask and IN_IGNORED) > 0:
                    if w.wd >= 0:
                      certWatchList[i].wd = -1
                      discard inoty.inotify_rm_watch(w.wd)
                      logs.debug "certs watch remove: ", w.path.toString()
                      for d in w.idxList:
                        certUpdateFlags[d.idx].priv = true
                        certUpdateFlags[d.idx].chain = true

          for idx, flag in certUpdateFlags:
            if flag.priv and flag.chain:
              updateCerts(idx)

  when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
    SSL_load_error_strings()
    SSL_library_init()
    OpenSSL_add_all_algorithms()
    sslCtx = newSslCtx(selfSignedCertFallback = true)
    # sslCtx.SSL_CTX_free()

    proc serverNameCallback(ssl: SSL; out_alert: ptr cint; arg: pointer): cint {.cdecl.} =
      try:
        echo "workerThreadCtx.client.srvId=", workerThreadCtx.client.srvId
        let sitename = $SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
        debug "sitename=", sitename
        let certs = certsTable[][sitename]
        if certs.srvId != workerThreadCtx.client.srvId:
          return SSL_TLSEXT_ERR_NOACK
        let ctx = siteCtxs[certs.idx].ctx
        if SSL_set_SSL_CTX(ssl, ctx).isNil:
          logs.error "error: SSL_set_SSL_CTX site=", sitename
          return SSL_TLSEXT_ERR_NOACK
        return SSL_TLSEXT_ERR_OK
      except:
        return SSL_TLSEXT_ERR_OK

    SSL_CTX_set_tlsext_servername_callback(sslCtx, serverNameCallback)

  proc serverWorker(arg: ThreadArg) {.thread.} =
    var events: array[cfg.epollEventsSize, EpollEvent]
    var evData: uint64
    #var sockAddress: Sockaddr_in
    #var addrLen = sizeof(sockAddress).SockLen
    #var recvBuf = newArray[byte](workerRecvBufSize)
    #var pClient: Client
    #var pRecvBuf: ptr UncheckedArray[byte]
    #var sock: SocketHandle = osInvalidSocket
    #var header: ReqHeader
    #var targetHeaders: Array[ptr tuple[id: HeaderParams, val: string]]

    var ctxObj: WorkerThreadCtxObj
    workerThreadCtx = cast[WorkerThreadCtx](addr ctxObj)
    var ctx = cast[WorkerThreadCtx](addr ctxObj)
    ctx.addrLen = sizeof(ctx.sockAddress).SockLen
    ctx.recvBuf = newArray[byte](workerRecvBufSize)
    for i in 0..<TargetHeaders.len:
      ctx.targetHeaders.add(addr TargetHeaders[i])

    ctx.threadId = arg.workerParams.threadId

    serverWorkerInit()

    var pevents: ptr UncheckedArray[EpollEvent] = cast[ptr UncheckedArray[EpollEvent]](addr events[0])
    var pRecvBuf0 = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[0])
    var skip = false
    var nfd: cint

    ctx.pRecvBuf0 = pRecvBuf0

    when cfg.sslLib != None:
      while active:
        nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                        cfg.epollEventsSize.cint, -1.cint)
        for i in 0..<nfd:
          try:
            ctx.client = cast[Client](pevents[i].data)
            cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
          except:
            let e = getCurrentException()
            logs.error e.name, ": ", e.msg

    else:
      while active:
        if ctx.threadId == 1:
          nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                          cfg.epollEventsSize.cint, -1.cint)
          if not throttleChanged and nfd >= 7:
            throttleChanged = true
            discard sem_post(addr throttleBody)
        else:
          if skip:
            nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                            cfg.epollEventsSize.cint, 10.cint)
          else:
            discard sem_wait(addr throttleBody)
            if highGear:
              nfd = 0
            else:
              skip = true
              nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                              cfg.epollEventsSize.cint, 0.cint)
              throttleChanged = false
          if nfd == 0 and not highGear:
            skip = false
            continue

        for i in 0..<nfd:
          try:
            ctx.client = cast[Client](pevents[i].data)
            cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
          except:
            let e = getCurrentException()
            logs.error e.name, ": ", e.msg

        if highGear:
          var assinged = atomic_fetch_add(addr highGearManagerAssinged, 1, 0)
          if assinged == 0:
            while highGear:
              var nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                                  cfg.epollEventsSize.cint, 1000.cint)
              if nfd > 0:
                var i = 0
                while true:
                  ctx.client = cast[Client](pevents[i].data)
                  if ctx.client.listenFlag:
                    cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
                    if highGear and (cfg.clientMax - FreePoolServerUsedCount) - clientFreePool.count < highGearThreshold:
                      highGear = false
                  else:
                    clientQueue.send(ctx.client)
                  inc(i)
                  if i >= nfd: break
              else:
                if clientQueue.count > 0:
                  for i in 0..<serverWorkerNum:
                    clientQueue.sendFlush()

            if clientQueue.count > 0:
              for i in 0..<serverWorkerNum:
                clientQueue.sendFlush()
            while true:
              ctx.client = clientQueue.popSafe()
              if ctx.client.isNil:
                break
              cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)

            for i in 0..<serverWorkerNum:
              clientQueue.sendFlush()
            while true:
              if highGearManagerAssinged == 1:
                atomic_fetch_sub(addr highGearManagerAssinged, 1, 0)
                break
              sleep(10)
              clientQueue.sendFlush()

          else:
            while true:
              ctx.client = clientQueue.recv(highGear)
              if ctx.client.isNil: break
              cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
            atomic_fetch_sub(addr highGearManagerAssinged, 1, 0)

      discard sem_post(addr throttleBody)

template httpTargetHeaderDefault() {.dirty.} =
  when not declared(TargetHeaderParams):
    HttpTargetHeader:
      HeaderHost: "Host"

template serverStartWithCfg(cfg: static Config) =
  httpTargetHeaderDefault()
  serverType()
  serverLib(cfg)
  startTimeStampUpdater()
  when cfg.sslLib != None:
    var fileWatcherThread: Thread[WrapperThreadArg]
    createThread(fileWatcherThread, threadWrapper, (fileWatcher, ThreadArg(type: ThreadArgType.Void)))

  let cpuCount = countProcessors()
  when cfg.serverWorkerNum < 0:
    serverWorkerNum = cpuCount
  else:
    serverWorkerNum = cfg.serverWorkerNum
  echo "server workers: ", serverWorkerNum, "/", cpuCount

  highGearThreshold = serverWorkerNum * 3

  var threads = newSeq[Thread[WrapperThreadArg]](serverWorkerNum)
  for i in 0..<serverWorkerNum:
    createThread(threads[i], threadWrapper, (serverWorker,
      ThreadArg(type: ThreadArgType.WorkerParams, workerParams: (i + 1, workerRecvBufSize))))

  joinThreads(threads)
  for i in countdown(releaseOnQuitEpfds.high, 0):
    let retEpfdClose = releaseOnQuitEpfds[i].close()
    if retEpfdClose != 0:
      logs.error "error: close epfd=", epfd, " ret=", retEpfdClose, " ", getErrnoStr()
  freeClient(cfg.clientMax)
  when cfg.sslLib != None:
    freeFileWatcher()
    joinThread(fileWatcherThread)
  joinThread(contents.timeStampThread)

template serverStart*() = serverStartWithCfg(cfg)

template serverStop*() =
  active = false
  highGear = false
  for i in countdown(releaseOnQuitSocks.high, 0):
    let retShutdown = releaseOnQuitSocks[i].shutdown(SHUT_RD)
    if retShutdown != 0:
      logs.error "error: quit shutdown ret=", retShutdown, " ", getErrnoStr()
  stopTimeStampUpdater()

{.passC: "-flto".}
{.passL: "-flto".}

#[
when isMainModule:
  onSignal(SIGINT, SIGTERM):
    debug "bye from signal ", sig
    serverStop()

  signal(SIGPIPE, SIG_IGN)

  setRlimitOpenFiles(RLIMIT_OPEN_FILES)
  #start()

  HttpTargetHeader:
    HeaderHost: "Host"
    HeaderUserAgent: "User-Agent"
    HeaderAcceptEncoding: "Accept-Encoding"
    HeaderConnection: "Connection"

  const d0 = "abcdefghijklmnopqrstuvwxyz"
  const notFound0 = "Not found".addDocType()

  var d = cast[Array[byte]]("Hello, world!".addHeader(Status200, "text/plain").toArray)

  proc updateTimeStamp() {.thread.} =
    while active:
      writeTimeStamp(cast[ptr UncheckedArray[byte]](addr d[49]))
      sleep(1000)

  var updateTimeStampThread: Thread[void]
  createThread(updateTimeStampThread, updateTimeStamp)

  addServer("0.0.0.0", 8009):
    routes:
      get "/":
        return send(d)

      var notFound = notFound0.addHeader(Status404)
      return send(notFound)

    stream:
      discard

  serverStart()
  joinThread(updateTimeStampThread)
]#
