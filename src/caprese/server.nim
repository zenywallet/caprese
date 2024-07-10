# Copyright (c) 2021 zenywallet

import std/macros
import std/nativesockets
import std/posix
import std/base64
import std/cpuinfo
import std/os
import std/strutils
import std/options
when NimMajor >= 2:
  import checksums/sha1
else:
  import std/sha1
import logs
import arraylib
import bytes
import files
import server_types
import config
export arraylib
export bytes
export server_types

var routesHostParamExists* {.compileTime.}: bool = false
var streamBlockExists* {.compileTime.}: bool = false
var responceCallExists* {.compileTime.}: bool = false
var postExists* {.compileTime.}: bool = false
var otherRequestMethodExists* {.compileTime.}: bool = false

macro HttpTargetHeader(idEnumName, valListName, targetHeaders, body: untyped): untyped =
  var enumParams = nnkEnumTy.newTree(newEmptyNode())
  var targetParams = nnkBracket.newTree()
  var addHeadersStmt = nnkStmtList.newTree()
  var internalEssentialHeaders: seq[tuple[headerId: string, headerString: string]]
  if routesHostParamExists:
    internalEssentialHeaders.add(("InternalEssentialHeaderHost", "Host"))
  internalEssentialHeaders.add(("InternalEssentialHeaderConnection", "Connection"))
  if streamBlockExists:
    internalEssentialHeaders.add(("InternalSecWebSocketKey", "Sec-WebSocket-Key"))
    internalEssentialHeaders.add(("InternalSecWebSocketProtocol", "Sec-WebSocket-Protocol"))
    internalEssentialHeaders.add(("InternalSecWebSocketVersion", "Sec-WebSocket-Version"))
  if responceCallExists:
    internalEssentialHeaders.add(("InternalAcceptEncoding", "Accept-Encoding"))
    internalEssentialHeaders.add(("InternalIfNoneMatch", "If-None-Match"))
  if postExists or otherRequestMethodExists:
    internalEssentialHeaders.add(("InternalContentLength", "Content-Length"))
    #internalEssentialHeaders.add(("InternalTransferEncoding", "Transfer-Encoding"))
  var internalEssentialConst = nnkStmtList.newTree()

  for a in body:
    var a0 = a[0]
    var paramLit = newLit($a[1][0] & ": ")
    enumParams.add(a0)
    targetParams.add(paramLit)
    addHeadersStmt.add quote do:
      `targetHeaders`.add((id: `a0`, val: `paramLit`))

  for a in body:
    for i, b in internalEssentialHeaders:
      if eqIdent(a[1][0], b[1]):
        var b0 = newIdentNode(b[0])
        var a0 = newIdentNode($a[0])
        internalEssentialConst.add quote do:
          const `b0` = `a0`
        internalEssentialHeaders.delete(i)
        break

  for b in internalEssentialHeaders:
    var b0 = newIdentNode(b[0])
    var compareVal = newLit(b[1] & ": ")
    enumParams.add(b0)
    targetParams.add(compareVal)
    addHeadersStmt.add quote do:
      `targetHeaders`.add((id: `b0`, val: `compareVal`))

  var addHeadersStmtLen = newLit(addHeadersStmt.len)
  quote do:
    type `idEnumName` = `enumParams`
    `internalEssentialConst`
    const `valListName` = `targetParams`
    var `targetHeaders`: Array[tuple[id: HeaderParams, val: string]]
    `targetHeaders`.newArrayOfCap(`addHeadersStmtLen`)
    `addHeadersStmt`

macro HttpTargetHeader*(body: untyped): untyped =
  quote do:
    HttpTargetHeader(HeaderParams, TargetHeaderParams, TargetHeaders, `body`)

var clientExtRec {.compileTime.} = nnkRecList.newTree()

macro clientExt*(body: untyped): untyped =
  for n in body[2][2]:
    clientExtRec.add(n)
  body[0][1].add(ident("used"))
  body

macro clientObjTypeMacro*(cfg: static Config): untyped =
  result = quote do:
    type
      ClientSendProc {.inject.} = proc (client: Client, data: ptr UncheckedArray[byte], size: int): SendResult {.thread.}

      KeepAliveStatus {.pure, inject.} = enum
        Unknown
        True
        False

      ClientBase* {.inject.} = ref object of RootObj
        sock*: SocketHandle
        recvBuf: ptr UncheckedArray[byte]
        recvBufSize: int
        recvCurSize: int
        sendBuf: ptr UncheckedArray[byte]
        sendCurSize: int
        keepAlive: bool
        keepAlive2: KeepAliveStatus
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
        dirty: int

      ClientObj* {.inject.} = object of ClientBase
        payloadSize: int
        when `cfg`.sslLib == BearSSL:
          sc: ptr br_ssl_server_context
          keyType: cint
        elif `cfg`.sslLib == OpenSSL or `cfg`.sslLib == LibreSSL or `cfg`.sslLib == BoringSSL:
          ssl: SSL
          sslErr: int
        pStream*: pointer
        proxy: Proxy

      Client* {.inject.} = ptr ClientObj

  for n in clientExtRec:
    result[3][2][2].add(n)  # append to ClientObj

template serverInit*() {.dirty.} =
  import std/epoll
  import std/locks
  import ptlock
  import logs
  import proxy

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

  clientObjTypeMacro(cfg)

  const ClientDirtyNone = 0
  const ClientDirtyTrue = 1
  const ClientDirtyMole = 2

type
  WebSocketOpCode* = enum
    Continue = 0x0
    Text = 0x1
    Binary = 0x2
    Close = 0x8
    Ping = 0x9
    Pong = 0xa

  ThreadArgType* {.pure.} = enum
    Void
    WorkerParams

  ThreadArg* = object
    case argType*: ThreadArgType
    of ThreadArgType.Void:
      discard
    of ThreadArgType.WorkerParams:
      workerParams*: tuple[threadId: int, bufLen: int]

  ServerError* = object of CatchableError
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

var active = true
var epfd*: cint = -1

type
  WrapperThreadArg = tuple[threadFunc: proc (arg: ThreadArg) {.thread.}, arg: ThreadArg]

  Tag* = Array[byte]

  TagRef* = object
    tag: ptr Tag
    idx: int

proc getErrnoStr*(): string =
  case errno
  of EADDRINUSE: "errno=EADDRINUSE(" & $errno & ")"
  else: "errno=" & $errno

template serverTagLib*(cfg: static Config) {.dirty.} =
  import std/posix
  from bytes as capbytes import nil
  import hashtable

  type
    ClientTaskCmd* {.pure.} = enum
      None
      Data

    ClientTask* = object
      case cmd*: ClientTaskCmd
      of ClientTaskCmd.None:
        discard
      of ClientTaskCmd.Data:
        data*: Array[byte]

  proc toUint64(tag: Tag): uint64 = capbytes.toUint64(tag.toSeq)

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

  proc getClient*(clientId: ClientId): Client =
    withWriteLock clientsLock:
      let pair = pendingClients.get(clientId)
      if not pair.isNil:
        result = pair.val

  proc markPending*(client: Client): ClientId {.discardable.} =
    withWriteLock clientsLock:
      if client.clientId == INVALID_CLIENT_ID:
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
      else:
        result = client.clientId

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
          var ca: Array[ClientId]
          ca.newArray(1)
          ca[0] = clientId
          clientIdsPair = tag2ClientIds.set(tag, ca)
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
    var clientIds: HashTableData[Tag, Array[ClientId]]
    withReadLock clientsLock:
      clientIds = tag2ClientIds.get(tag)
    if not clientIds.isNil:
      for c in clientIds.val:
        yield c

  iterator getTags*(clientId: ClientId): Tag =
    var tagRefs: HashTableData[ClientId, Array[TagRef]]
    withReadLock clientsLock:
      tagRefs = clientId2Tags.get(clientId)
    if not tagRefs.isNil:
      for t in tagRefs.val:
        yield t.tag[]

  proc addTask*(clientId: ClientId, task: ClientTask) =
    withWriteLock clientsLock:
      let tasksPair = clientId2Tasks.get(clientId)
      if tasksPair.isNil:
        var ta: Array[ClientTask]
        ta.newArray(1)
        ta[0] = task
        clientId2Tasks.set(clientId, ta)
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

  proc getAndPurgeTasks*(clientId: ClientId, cb: proc(task: ClientTask): bool {.gcsafe.}): bool =
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
    when cfg.sslLib == BearSSL:
      if client.sc.isNil:
        acquire(client.spinLock)
        if not client.appShift:
          inc(client.appId)
          client.appShift = true
        client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
        release(client.spinLock)

        var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
        if retCtl != 0:
          return false
        return true

      else:
        acquire(client.spinLock)
        if client.threadId == 0:
          release(client.spinLock)

          var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
          if retCtl != 0:
            return false
          return true
        else:
          client.dirty = ClientDirtyTrue
          release(client.spinLock)
          return true

    else:
      acquire(client.spinLock)
      if not client.appShift:
        inc(client.appId)
        client.appShift = true
      client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
      release(client.spinLock)

      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
      if retCtl != 0:
        return false
      return true

  proc send*(clientId: ClientId, data: seq[byte] | string | Array[byte]): SendResult {.discardable.} =
    let pair = pendingClients.get(clientId)
    if pair.isNil:
      return SendResult.None
    let client = pair.val
    if client.isNil:
      return SendResult.None

    when data is Array[byte]:
      clientId.addTask(ClientTask(cmd: ClientTaskCmd.Data, data: data))
    elif data is string:
      clientId.addTask(ClientTask(cmd: ClientTaskCmd.Data, data: cast[seq[byte]](data).toArray))
    else:
      clientId.addTask(ClientTask(cmd: ClientTaskCmd.Data, data: data.toArray))
    if client.invokeSendEvent():
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
      if nextSize > staticInt(cfg.recvBufExpandBreakSize):
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
    when data is Array:
      var data = data.toSeq
    var finOp = 0x80.byte or opcode.byte
    if dataLen < 126:
      frame = capbytes.BytesBE(finOp, dataLen.byte, data)
    elif dataLen <= 0xffff:
      frame = capbytes.BytesBE(finOp, 126.byte, dataLen.uint16, data)
    else:
      frame = capbytes.BytesBE(finOp, 127.byte, dataLen.uint64, data)
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
      frame = capbytes.BytesBE(finOp, dataLen.byte, data)
    elif dataLen <= 0xffff:
      frame = capbytes.BytesBE(finOp, 126.byte, dataLen.uint16, data)
    else:
      frame = capbytes.BytesBE(finOp, 127.byte, dataLen.uint64, data)
    result = clientId.send(frame.toString())

  template send(data: seq[byte] | string | Array[byte]): SendResult {.dirty, used.} = ctx.client.send(data)

  template wsSend(data: seq[byte] | string | Array[byte],
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.dirty, used.} =
    client.wsServerSend(data, opcode)

  template wsSend(data: ptr UncheckedArray[byte], size: int,
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.dirty, used.} =
    client.wsServerSend(data.toString(size), opcode)

  template wsSend(clientId: ClientId, data: seq[byte] | string | Array[byte],
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.dirty, used.} =
    clientId.wsServerSend(data, opcode)

  template wsSend(clientId: ClientId, data: ptr UncheckedArray[byte], size: int,
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.dirty, used.} =
    clientId.wsServerSend(data.toString(size), opcode)

  proc wsSend0(tag: Tag, data: seq[byte] | string | Array[byte],
              opcode: WebSocketOpCode = WebSocketOpCode.Binary): SendResult {.used.} =
    result = SendResult.Success
    for cid in tag.getClientIds():
      let ret = cid.wsServerSend(data, opcode)
      if ret == SendResult.Pending:
        result = SendResult.Pending

  template wsSendTag*(tag: Tag, data: seq[byte] | string | Array[byte],
                    opcode: WebSocketOpCode = WebSocketOpCode.Binary): int =
    var sendCount = 0
    let clientIds = tag.getClientIds()
    if clientIds.len > 0:
      let sendData = data
      for cid in clientIds:
        let ret = cid.wsServerSend(sendData, opcode)
        if ret == SendResult.Pending or ret == SendResult.Success:
          inc(sendCount)
    sendCount

  template wsSend*(tag: Tag, data: seq[byte] | string | Array[byte],
                  opcode: WebSocketOpCode = WebSocketOpCode.Binary): int =
    wsSendTag(tag, data, opcode)

var abort*: proc() {.thread.} = proc() {.thread.} = active = false

template serverInitFreeClient() {.dirty.} =
  import queue2

  var clients: ptr UncheckedArray[ClientObj] = nil
  var clientFreePool* = queue2.newQueue[Client]()

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
      when cfg.sslLib == BearSSL:
        p[i].sc = nil
        p[i].keyType = 0.cint
      elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
        p[i].ssl = nil
        p[i].sslErr = SSL_ERROR_NONE
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
      when cfg.sslLib == BearSSL:
        if not client.sc.isNil:
          deallocShared(cast[pointer](client.sc))
          client.sc = nil
        client.keyType = 0.cint
      elif ssl and (cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL):
        if not client.ssl.isNil:
          SSL_free(client.ssl)
          client.ssl = nil
          client.sslErr = SSL_ERROR_NONE
      sock.close()
      client.recvCurSize = 0
      client.recvBufSize = 0
      if not client.proxy.isNil:
        client.proxy.shutdown()
        client.proxy = nil
      if not client.recvBuf.isNil:
        deallocShared(cast[pointer](client.recvBuf))
        client.recvBuf = nil
      if not client.sendBuf.isNil:
        deallocShared(cast[pointer](client.sendBuf))
        client.sendBuf = nil
      client.keepAlive = true
      client.payloadSize = 0
      client.appShift = false
      when cfg.sslLib == SslLib.None:
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

proc createServer(bindAddress: string, port: uint16, reusePort: bool = false): SocketHandle =
  var aiList: ptr AddrInfo
  try:
    aiList = getAddrInfo(bindAddress, port.Port, Domain.AF_UNSPEC)
  except:
    errorRaise "error: getaddrinfo ", getErrnoStr(), " bind=", bindAddress, " port=", port
  let domain = aiList.ai_family.toKnownDomain.get
  let sock = createNativeSocket(domain)
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

proc createServer(unixDomainSockFile: string): SocketHandle =
  let sock = socket(Domain.AF_UNIX.cint, posix.SOCK_STREAM, 0)
  var sa: Sockaddr_un
  sa.sun_family = Domain.AF_UNIX.TSa_Family
  if unixDomainSockFile.len > sa.sun_path.len:
    errorRaise "error: unix domain socket file is too long"
  var ss: Stat
  if stat(unixDomainSockFile, ss) == 0 and S_ISSOCK(ss.st_mode):
    removeFile(unixDomainSockFile)
  copyMem(addr sa.sun_path[0], unsafeAddr unixDomainSockFile[0], unixDomainSockFile.len)
  let retBind = sock.bindSocket(cast[ptr SockAddr](addr sa), sizeof(sa).SockLen)
  if retBind < 0:
    errorRaise "error: bind ret=", retBind, " ", getErrnoStr()

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

var releaseOnQuitSocks: Array[SocketHandle]
var releaseOnQuitEpfds: Array[cint]

proc addReleaseOnQuit(sock: SocketHandle) = releaseOnQuitSocks.add(sock)

proc addReleaseOnQuit(epfd: cint) = releaseOnQuitEpfds.add(epfd)

type
  AppType* = enum
    AppDummy
    AppListen
    AppRoutes
    AppRoutesStage1
    AppRoutesStage2
    AppRoutesSend
    AppStream
    AppStreamSend
    AppProxy
    AppProxySend

var initServerFlag* {.compileTime.} = false
var curSrvId {.compileTime.} = 0
var curAppId {.compileTime.} = 0
var curResId {.compileTime.} = 0
var serverConfigStmt* {.compileTime.} = newStmtList()
var serverStmt* {.compileTime.} = newStmtList()
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
var serverHandlerList* {.compileTime.} = @[("appDummy", ident("false"), ident("false"), newStmtList())]
var appIdTypeList* {.compileTime.} = @[AppDummy]
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
      when NimVersion == "2.0.4": # workaround modulepaths.nim/getModuleName degrade
        import std.tables
      else:
        import std/tables
      serverInitFreeClient()
      initClient(staticInt(cfg.clientMax), ClientObj, Client)
  else:
    quote do:
      discard

macro getAppId*(): int =
  inc(curAppId)
  newLit(curAppId)

proc findColonNum(s: string): bool {.compileTime.} =
  var findmColonNum = 0
  for i in countdown(s.len-1, 0):
    if isDigit(s[i]):
      findmColonNum = 1
    elif findmColonNum == 1 and s[i] == ':':
      findmColonNum = 2
      break
    else:
      findmColonNum = 0
      break
  if findmColonNum == 2: true else: false

macro addServerMacro*(bindAddress: string, port: uint16, unix: bool, ssl: bool, sslLib: SslLib, body: untyped = newEmptyNode()): untyped =
  if boolVal(ssl) and eqIdent("None", sslLib):
    macros.error("server ssl = ture, but config.sslLib = None")
  inc(curSrvId)
  var srvId = curSrvId
  inc(curAppId)
  var appId = curAppId
  serverHandlerList.add(("appListen", ssl, unix, newStmtList()))
  appIdTypeList.add(AppListen)
  inc(curAppId) # reserved
  var appRoutes = curAppId
  serverHandlerList.add(("appRoutes", ssl, unix, newStmtList()))
  appIdTypeList.add(AppRoutes)
  if boolVal(ssl) and (eqIdent("OpenSSL", sslLib) or eqIdent("LibreSSL", sslLib) or eqIdent("BoringSSL", sslLib)):
    inc(curAppId)
    appRoutes = curAppId
    serverHandlerList.add(("appRoutesStage1", ssl, unix, newStmtList()))
    appIdTypeList.add(AppRoutesStage1)
    inc(curAppId)
    serverHandlerList.add(("appRoutesStage2", ssl, unix, newStmtList()))
    appIdTypeList.add(AppRoutesStage2)
  else:
    inc(curAppId)
    serverHandlerList.add(("appRoutesSend", ssl, unix, newStmtList()))
    appIdTypeList.add(AppRoutesSend)
  var serverResources = newStmtList()
  var routesList = newStmtList()
  for s in body:
    if eqIdent(s[0], "routes"):
      var hostname = ""
      var portInt = intVal(port)
      if s[1].kind == nnkStrLit:
        hostname = $s[1]
        if portInt > 0 and portInt != 80 and portInt != 443 and not findColonNum(hostname):
          s[1] = newLit(hostname & ":" & $portInt)
      elif s[1].kind == nnkExprEqExpr and eqIdent(s[1][0], "host"):
        hostname = $s[1][1]
        if portInt > 0 and portInt != 80 and portInt != 443 and not findColonNum(hostname):
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
          if s2[1].kind != nnkExprEqExpr or not eqIdent(s2[1][0], "streamAppId"):
            s2.insert(1, nnkExprEqExpr.newTree(
              newIdentNode("streamAppId"),
              newLit(streamAppId)
            ))
          if s2.len < 5:
            s2.insert(3, nnkExprEqExpr.newTree(
              newIdentNode("protocol"),
              newLit("")
            ))
          serverHandlerList.add(("appStream", ssl, unix, s2[s2.len - 1]))
          appIdTypeList.add(AppStream)
          inc(curAppId)
          serverHandlerList.add(("appStreamSend", ssl, unix, newStmtList()))
          appIdTypeList.add(AppStreamSend)
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
        elif eqIdent(s2[0], "proxy"):
          inc(curAppId)
          var proxyAppId = curAppId
          if s2[1].kind != nnkExprEqExpr or not eqIdent(s2[1][0], "proxyAppId"):
            s2.insert(1, nnkExprEqExpr.newTree(
              newIdentNode("proxyAppId"),
              newLit(proxyAppId)
            ))
            if s2[s2.len - 1].kind != nnkStmtList:
              s2.add(newBlockStmt(newStmtList()))
          serverHandlerList.add(("appProxy", ssl, unix, newStmtList()))
          appIdTypeList.add(AppProxy)
          inc(curAppId)
          if boolVal(ssl) and (eqIdent("OpenSSL", sslLib) or eqIdent("LibreSSL", sslLib) or eqIdent("BoringSSL", sslLib)):
            serverHandlerList.add(("appRoutesStage2", ssl, unix, newStmtList()))
          else:
            serverHandlerList.add(("appProxySend", ssl, unix, newStmtList()))
          appIdTypeList.add(AppProxySend)
        routesBody.add(s2)

      if not certsBlockFlag and boolVal(ssl):
        routesBody.insert 0, quote do:
          certificates(`srvId`, `hostname`, "")

      routesBase[routesBase.len - 1] = routesBody
      routesList.add(routesBase)
    else:
      serverWorkerInitStmt.add(s)
    serverHandlerList[appRoutes][3] = routesList

  inc(freePoolServerUsedCount)

  quote do:
    `serverResources`

    var serverSock = when `unix`: createServer(`bindAddress`) else: createServer(`bindAddress`, `port`)

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
    when cfg.sslLib == SslLib.None:
      newClient.listenFlag = true
    newClient.ev.events = EPOLLIN or EPOLLEXCLUSIVE
    var retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, serverSock, addr newClient.ev)
    if retCtl != 0:
      errorRaise "error: addServer epoll_ctl ret=", retCtl, " ", getErrnoStr()


macro evalSslLib(val: SslLib): SslLib =
  quote do:
    when `val` == BearSSL: BearSSL
    elif `val` == OpenSSL: OpenSSL
    elif `val` == LibreSSL: LibreSSL
    elif `val` == BoringSSL: BoringSSL
    else: None

template addServer*(bindAddress: string, port: uint16, unix: bool, ssl: bool, body: untyped) =
  initServer()
  addServerMacro(bindAddress, port, unix, ssl, evalSslLib(cfg.sslLib), body)

macro serverConfigMacro*(): untyped = serverConfigStmt

macro serverMacro*(): untyped = serverStmt

macro serverWorkerInit*(): untyped = serverWorkerInitStmt

macro mainServerHandlerMacro*(appId: typed): untyped =
  serverWorkerMainStmt[0][0] = newIdentNode($appId)
  serverWorkerMainStmt


template routes*(host: string, body: untyped) =
  if reqHost() == host:
    body

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
            let ret = send(webSocketMessage(key))
            getOnOpenBody(body)
            return ret
        else:
          return SendResult.Error
      else:
        let prot = getHeaderValue(InternalSecWebSocketProtocol)
        when protocol.len > 0:
          if prot == protocol:
            reqClient()[].appId = streamAppId
            let ret = send(webSocketMessageProtocol(key, protocol))
            getOnOpenBody(body)
            return ret
          else:
            return SendResult.Error
        else:
          reqClient()[].appId = streamAppId
          let ret = if prot.len > 0:
            send(webSocketMessageProtocol(key, prot))
          else:
            send(webSocketMessage(key))
          getOnOpenBody(body)
          return ret

template public*(importPath: string, body: untyped) = body

template content*(content, mime: string): FileContent =
  createStaticFile(content, mime)

template content*(content: string): FileContent =
  createStaticFile(content, "text/html")

template proxy*(path, host: string, port: uint16) = discard

template proxy*(path, host: string, port: uint16, body: untyped) = discard

template proxy*(path, unix: string) = discard

template proxy*(path, unix: string, body: untyped) = discard

template proxy*(proxyAppId: int, path, host: string, port: uint16, body: untyped) =
  if startsWith(reqUrl(), path):
    body
    let client = ctx.client
    if client.proxy.isNil:
      client.proxy = newProxy(host, port.Port)
      client.proxy.originalClientId = client.markPending()
      let sendRet = if client.recvCurSize > 0:
        client.proxy.send(cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]), client.recvCurSize, false)
      else:
        client.proxy.send(ctx.pRecvBuf0, ctx.recvDataSize, false)
      if sendRet == SendResult.None or sendRet == SendResult.Error:
        return sendRet
      client.appId = proxyAppId
      client.proxy.setRecvCallback(proxyRecvCallback, true)
    else:
      let sendRet = if client.recvCurSize > 0:
        client.proxy.send(cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]), client.recvCurSize)
      else:
        client.proxy.send(ctx.pRecvBuf0, ctx.recvDataSize)
      if sendRet == SendResult.None or sendRet == SendResult.Error:
        return sendRet
      client.appId = proxyAppId
    return SendResult.Pending

template proxy*(proxyAppId: int, path, unix: string, body: untyped) =
  if startsWith(reqUrl(), path):
    body
    let client = ctx.client
    if client.proxy.isNil:
      client.proxy = newProxy(unix)
      client.proxy.originalClientId = client.markPending()
      let sendRet = if client.recvCurSize > 0:
        client.proxy.send(cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]), client.recvCurSize)
      else:
        client.proxy.send(ctx.pRecvBuf0, ctx.recvDataSize)
      if sendRet == SendResult.None or sendRet == SendResult.Error:
        return sendRet
      client.appId = proxyAppId
      client.proxy.setRecvCallback(proxyRecvCallback)
    else:
      let sendRet = if client.recvCurSize > 0:
        client.proxy.send(cast[ptr UncheckedArray[byte]](addr client.recvBuf[0]), client.recvCurSize)
      else:
        client.proxy.send(ctx.pRecvBuf0, ctx.recvDataSize)
      if sendRet == SendResult.None or sendRet == SendResult.Error:
        return sendRet
      client.appId = proxyAppId    
    return SendResult.Pending

template serverType() {.dirty.} =
  type
    ReqHeader = object
      url: string
      params: array[TargetHeaderParams.len, tuple[cur: int, size: int]]
      minorVer: int

var serverThreadCtxExtRec {.compileTime.} = nnkRecList.newTree()

macro serverThreadCtxExt*(body: untyped): untyped =
  for n in body[2][2]:
    serverThreadCtxExtRec.add(n)
  body[0][1].add(ident("used"))
  body

macro serverThreadCtxObjTypeMacro*(cfg: static Config): untyped =
  result = quote do:
    type
      ServerThreadCtxObj {.inject.} = object
        sockAddress: Sockaddr_in
        addrLen: SockLen
        recvBuf: Array[byte]
        events: uint32
        client: Client
        pRecvBuf: ptr UncheckedArray[byte]
        header: ReqHeader
        targetHeaders: Array[ptr tuple[id: HeaderParams, val: string]]
        pRecvBuf0: ptr UncheckedArray[byte]
        recvDataSize: int
        threadId: int
        reqMethodPos: int
        reqMethodLen: int
        nextPos: int
        parseSize: int
        data: ptr UncheckedArray[byte]
        size: int

  for n in serverThreadCtxExtRec:
    result[0][2][2].add(n)  # append to ServerThreadCtxObj

template serverLib(cfg: static Config) {.dirty.} =
  import std/re
  import std/strutils
  import std/sequtils
  when NimMajor >= 2:
    import checksums/sha1
  else:
    import std/sha1

  mixin addSafe, popSafe

  const FreePoolServerUsedCount = freePoolServerUsedCount

  serverThreadCtxObjTypeMacro(cfg)

  type
    ServerThreadCtx = ptr ServerThreadCtxObj
    ClientHandlerProc = proc (ctx: ServerThreadCtx) {.thread.}

  var serverThreadCtx {.threadvar.}: ServerThreadCtx
  #var clientHandlerProcs: Array[ClientHandlerProc]

  when cfg.sslLib == SslLib.None and cfg.connectionPreferred != ConnectionPreferred.InternalConnection:
    var clientQueue = queue2.newQueue[Client]()
  var highGearManagerAssigned: int = 0
  var highGearSemaphore: Sem
  discard sem_init(addr highGearSemaphore, 0, 0)
  #discard sem_destroy(addr highGearSemaphore)
  var throttleBody: Sem
  discard sem_init(addr throttleBody, 0, 0)
  #discard sem_destroy(addr throttleBody)
  when cfg.sslLib == SslLib.None and cfg.connectionPreferred != ConnectionPreferred.InternalConnection:
    var throttleChanged: bool = false
  var highGearThreshold: int

  when cfg.sslLib == SslLib.None and cfg.connectionPreferred != ConnectionPreferred.InternalConnection:
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

  proc echoHeader(buf: ptr UncheckedArray[byte], size: int, header: ReqHeader) {.used.} =
    echo "url: ", header.url
    for i, param in header.params:
      echo i.HeaderParams, " ", TargetHeaderParams[i], capbytes.toString(cast[ptr UncheckedArray[byte]](addr buf[param.cur]), param.size)

  proc getHeaderValue(buf: ptr UncheckedArray[byte], reqHeader: ReqHeader, paramId: HeaderParams): string =
    let param = reqHeader.params[paramId.int]
    result = capbytes.toString(cast[ptr UncheckedArray[byte]](addr buf[param.cur]), param.size)

  proc parseHeader(buf: ptr UncheckedArray[byte], size: int,
                  targetHeaders: var Array[ptr tuple[id: HeaderParams, val: string]]
                  ): tuple[err: int, header: ReqHeader, next: int] =
    if (when cfg.urlRootSafe: equalMem(addr buf[0], "GET /".cstring, 5) else: equalMem(addr buf[0], "GET ".cstring, 4)):
      var cur = 4
      var pos = 5
      while true:
        if equalMem(addr buf[pos], " HTTP/1.".cstring, 8):
          result.header.url = capbytes.toString(cast[ptr UncheckedArray[byte]](addr buf[cur]), pos - cur)
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

  type
    RequestMethod* = enum
      Unknown
      GET
      HEAD
      POST
      PUT
      DELETE
      CONNECT
      OPTIONS
      TRACE

  proc parseHeader(buf: ptr UncheckedArray[byte], size: int,
                  targetHeaders: var Array[ptr tuple[id: HeaderParams, val: string]],
                  header: var ReqHeader
                  ): tuple[err: int, next: int] =
    if (when cfg.urlRootSafe: equalMem(addr buf[0], "GET /".cstring, 5) else: equalMem(addr buf[0], "GET ".cstring, 4)):
      var cur = 4
      var pos = 5
      while true:
        if equalMem(addr buf[pos], " HTTP/1.".cstring, 8):
          header.url = capbytes.toString(cast[ptr UncheckedArray[byte]](addr buf[cur]), pos - cur)
          inc(pos, 8)
          if equalMem(addr buf[pos], "1\c\L".cstring, 3):
            header.minorVer = 1
            inc(pos, 3)
          elif equalMem(addr buf[pos], "0\c\L".cstring, 3):
            header.minorVer = 0
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
            header.minorVer = minorVer
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
                  header.params[headerId.int] = (cur, pos - cur)
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

  template parseHeader2(buf: ptr UncheckedArray[byte], size: int,
                  targetHeaders: var Array[ptr tuple[id: HeaderParams, val: string]],
                  header: var ReqHeader
                  ): int =
    var next {.noInit.}: int
    block parseMain:
      let cur0 = cast[uint](addr buf[0])
      if equalMem(cast[pointer](cur0), "GET ".cstring, 4):
        var cur = cur0 + 4
        var pos = cur + 1
        while true:
          if equalMem(cast[pointer](pos), " HTTP/1.".cstring, 8):
            when cfg.urlRootSafe:
              if cast[ptr char](cast[pointer](cur))[] != '/':
                next = -1
                break
            header.url = capbytes.toString(cast[ptr UncheckedArray[byte]](cast[pointer](cur)), pos - cur)
            inc(pos, 7)
            if equalMem(cast[pointer](pos), ".1\c\L".cstring, 4):
              header.minorVer = 1
              inc(pos, 2)
              if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                next = (pos + 4.uint - cur0).int
                break
            elif equalMem(cast[pointer](pos), ".0\c\L".cstring, 4):
              header.minorVer = 0
              inc(pos, 2)
              if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                next = (pos + 4.uint - cur0).int
                break
            else:
              inc(pos)
              let minorVer = int(cast[ptr char](cast[pointer](pos))[]) - int('0')
              if minorVer < 0 or minorVer > 9:
                next = -1
                break
              inc(pos)
              if not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                next = -1
                break
              inc(pos, 2)
              header.minorVer = minorVer
              if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                next = (pos + 2.uint - cur0).int
                break

            var incompleteIdx = 0
            while true:
              block paramsLoop:
                for i in incompleteIdx..<targetHeaders.len:
                  let (headerId, targetParam) = targetHeaders[i][]
                  if equalMem(cast[pointer](pos), targetParam.cstring, targetParam.len):
                    inc(pos, targetParam.len)
                    cur = pos
                    while not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                      inc(pos)
                    header.params[headerId.int] = ((cur - cur0).int, (pos - cur).int)
                    inc(pos, 2)
                    if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                      next = (pos + 2.uint - cur0).int
                      break parseMain
                    if i != incompleteIdx:
                      swap(targetHeaders[incompleteIdx], targetHeaders[i])
                    inc(incompleteIdx)
                    if incompleteIdx >= targetHeaders.len:
                      inc(pos)
                      while(not equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4)):
                        inc(pos)
                      next = (pos + 4.uint - cur0).int
                      break parseMain
                    break paramsLoop
                while not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                  inc(pos)
                inc(pos, 2)
                if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                  next = (pos + 2.uint - cur0).int
                  break parseMain

          elif equalMem(cast[pointer](pos), "\c\L".cstring, 2):
            next = -1
            break
          inc(pos)
      else:
        next = -1
    next

  template parseHeader3(buf: ptr UncheckedArray[byte], size: int,
                  targetHeaders: var Array[ptr tuple[id: HeaderParams, val: string]],
                  header: var ReqHeader
                  ): int =
    var next {.noInit.}: int
    block parseMain:
      let cur0 = cast[uint](addr buf[0])
      let last = cur0 + size.uint
      var pos = cur0 + 6
      if pos <= last and equalMem(cast[pointer](cur0), "POST /".cstring, 6):
        var cur = cur0 + 5
        pos = cur + 1
        while true:
          if pos + 8 <= last and equalMem(cast[pointer](pos), " HTTP/1.".cstring, 8):
            #when cfg.urlRootSafe:
            #  if cast[ptr char](cast[pointer](cur))[] != '/':
            #    next = -1
            #    break
            header.url = capbytes.toString(cast[ptr UncheckedArray[byte]](cast[pointer](cur)), pos - cur)
            inc(pos, 7)
            if pos + 4 > last:
              next = -1
              break
            if equalMem(cast[pointer](pos), ".1\c\L".cstring, 4):
              header.minorVer = 1
              inc(pos, 2)
              if pos + 4 > last:
                next = -1
                break
              if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                next = (pos + 4.uint - cur0).int
                break
            elif equalMem(cast[pointer](pos), ".0\c\L".cstring, 4):
              header.minorVer = 0
              inc(pos, 2)
              if pos + 4 > last:
                next = -1
                break
              if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                next = (pos + 4.uint - cur0).int
                break
            else:
              inc(pos)
              let minorVer = int(cast[ptr char](cast[pointer](pos))[]) - int('0')
              if minorVer < 0 or minorVer > 9:
                next = -1
                break
              inc(pos)
              if not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                next = -1
                break
              inc(pos, 2)
              if pos + 2 > last:
                next = -1
                break
              header.minorVer = minorVer
              if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                next = (pos + 2.uint - cur0).int
                break

            var incompleteIdx = 0
            while true:
              block paramsLoop:
                for i in incompleteIdx..<targetHeaders.len:
                  let (headerId, targetParam) = targetHeaders[i][]
                  if equalMem(cast[pointer](pos), targetParam.cstring, targetParam.len):
                    inc(pos, targetParam.len)
                    cur = pos
                    while not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                      inc(pos)
                    header.params[headerId.int] = ((cur - cur0).int, (pos - cur).int)
                    inc(pos, 2)
                    if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                      next = (pos + 2.uint - cur0).int
                      break parseMain
                    if i != incompleteIdx:
                      swap(targetHeaders[incompleteIdx], targetHeaders[i])
                    inc(incompleteIdx)
                    if incompleteIdx >= targetHeaders.len:
                      inc(pos)
                      while(not equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4)):
                        inc(pos)
                      next = (pos + 4.uint - cur0).int
                      break parseMain
                    break paramsLoop
                while not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                  inc(pos)
                inc(pos, 2)
                if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                  next = (pos + 2.uint - cur0).int
                  break parseMain

          elif equalMem(cast[pointer](pos), "\c\L".cstring, 2):
            next = -1
            break
          inc(pos)
      else:
        next = -1
    next

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
      payloadLen = capbytes.toUint16BE(data[2]).int
      frameHeadSize = 8
    elif payloadLen == 127:
      if size < 10:
        return (false, fin, opcode, nil, 0, data, size)
      payloadLen = capbytes.toUint64BE(data[2]).int # exception may occur. value out of range [RangeDefect]
      frameHeadSize = 14
    else:
      return (false, fin, opcode, nil, 0, data, size)

    var frameSize = frameHeadSize + payloadLen
    if frameSize > staticInt(cfg.maxFrameSize):
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

  template reqUrl: string {.used.} = ctx.header.url
  template headerUrl(): string {.used.} = ctx.header.url # deprecated

  template get(path: string, body: untyped) {.used.} =
    if reqUrl() == path:
      body

  template get(pathArgs: varargs[string], body: untyped) {.used.} =
    if reqUrl() in pathArgs:
      body

  template get(path: Regex, body: untyped) {.used.} =
    if reqUrl() =~ path:
      body

  template startsWith(path: string): bool {.used.} = startsWith(reqUrl(), path)

  template get(path: bool, body: untyped) {.used.} =
    if path:
      body

  template post(path: string, body: untyped) {.used.} =
    when cfg.postRequestMethod:
      {.warning: "POST is not yet implemented.".}
      if reqUrl() == path:
        body
    else:
      {.error: "POST is disabled. It can be enabled with postRequestMethod.".}

  template acme(path: static string, body: untyped) {.used.} =
    block:
      var (acmeFlag, content, mime) = getAcmeChallenge(path, ctx.header.url)
      if acmeFlag:
        body
        if content.len > 0:
          return send(content.addHeader(Status200, mime))

  template acme(path: static string) {.used.} =
    block:
      var (acmeFlag, content, mime) = getAcmeChallenge(path, ctx.header.url)
      if content.len > 0:
        return send(content.addHeader(Status200, mime))

  proc proxyRecvCallback(originalClientId: ClientId, buf: ptr UncheckedArray[byte], size: int) {.used.} =
    if size <= 0:
      let client = getClient(originalClientId)
      if not client.isNil:
        client.close(ssl = true)
    else:
      originalClientId.send(capbytes.toString(buf, size))

  template reqClient: Client {.used.} = ctx.client

  template reqHost: string {.used.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, InternalEssentialHeaderHost)

  template reqProtocol: string {.used.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, InternalSecWebSocketProtocol)

  template reqHeader(paramId: HeaderParams): string {.used.} =
    getHeaderValue(ctx.pRecvBuf, ctx.header, paramId)

  template reqMethod(): string {.used.} =
    cast[ptr UncheckedArray[byte]](addr ctx.pRecvBuf[ctx.reqMethodPos]).toString(ctx.reqMethodLen)

  template head(path: string, body: untyped) {.used.} =
    if reqUrl() == path and reqMethod() == $RequestMethod.HEAD:
      body

  template put(path: string, body: untyped) {.used.} =
    if reqUrl() == path and reqMethod() == $RequestMethod.PUT:
      body

  template delete(path: string, body: untyped) {.used.} =
    if reqUrl() == path and reqMethod() == $RequestMethod.DELETE:
      body

  template connect(path: string, body: untyped) {.used.} =
    if reqUrl() == path and reqMethod() == $RequestMethod.CONNECT:
      body

  template options(path: string, body: untyped) {.used.} =
    if reqUrl() == path and reqMethod() == $RequestMethod.OPTIONS:
      body

  template trace(path: string, body: untyped) {.used.} =
    if reqUrl() == path and reqMethod() == $RequestMethod.TRACE:
      body

  template getHeaderValue(paramId: HeaderParams): string =
    getHeaderValue(ctx.pRecvBuf, ctx.header, paramId)

  template response(file: FileContent, code: StatusCode = Status200): SendResult {.used.} =
    if reqHeader(InternalIfNoneMatch) == file.md5:
      send(Empty.addHeader(Status304))
    else:
      var acceptEnc = reqHeader(InternalAcceptEncoding).split(",")
      acceptEnc.apply(proc(x: string): string = x.strip)
      if acceptEnc.contains("br"):
        send(file.brotli.addHeader(EncodingType.Brotli, file.md5, code, file.mime))
      elif acceptEnc.contains("deflate"):
        send(file.deflate.addHeader(EncodingType.Deflate, file.md5, code, file.mime))
      else:
        send(file.content.addHeader(EncodingType.None, file.md5, code, file.mime))

  proc mainServerHandler(ctx: ServerThreadCtx, client: Client, pRecvBuf: ptr UncheckedArray[byte], header: ReqHeader): SendResult {.inline.} =
    let appId = client.appId - 1
    mainServerHandlerMacro(appId)

  proc appDummy(ctx: ServerThreadCtx) {.thread.} = discard

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
        let srcBytes = capbytes.toBytes(cast[ptr UncheckedArray[byte]](src), len)
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
        case keyType*: CertPrivateKeyType
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
        return CertPrivateKey(keyType: CertPrivateKeyType.None)

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
        return CertPrivateKey(keyType: CertPrivateKeyType.RSA, rsa: sk)

      of BR_KEYTYPE_EC:
        var ek = br_skey_decoder_get_ec(addr dc)
        var sk = cast[ptr br_ec_private_key](allocShared0(sizeof(br_ec_private_key)))
        sk.curve = ek.curve
        sk.x = cast[ptr uint8](allocShared0(ek.xlen))
        copyMem(sk.x, ek.x, ek.xlen)
        sk.xlen = ek.xlen
        zeroMem(addr dc, sizeof(br_skey_decoder_context))
        return CertPrivateKey(keyType: CertPrivateKeyType.EC, ec: sk)

      else:
        return CertPrivateKey(keyType: CertPrivateKeyType.None)

    proc freeCertPrivateKey(certPrivKey: var CertPrivateKey) =
      case certPrivKey.keyType
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
          certPrivKey = CertPrivateKey(keyType: CertPrivateKeyType.None)

      of CertPrivateKeyType.EC:
        if not certPrivKey.ec.isNil:
          zeroMem(certPrivKey.ec.x, certPrivKey.ec.xlen)
          deallocShared(certPrivKey.ec.x)
          zeroMem(certPrivKey.ec, sizeof(br_ec_private_key))
          deallocShared(certPrivKey.ec)
          certPrivKey.ec = nil
          certPrivKey = CertPrivateKey(keyType: CertPrivateKeyType.None)

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
        let srcBytes = capbytes.toBytes(cast[ptr UncheckedArray[byte]](src), len)
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
      if certKeyChains[].key.keyType == CertPrivateKeyType.None:
        debug "CertPrivateKeyType.None serverName=", serverName
        certKeyChains = addr certKeyChainsList[0]
      acquire(certKeyChainsListLock)
      let certKey = certKeyChains[].key
      let chains = certKeyChains[].chains
      release(certKeyChainsListLock)

      case certKey.keyType
      of CertPrivateKeyType.EC:
        serverThreadCtx.client.keyType = BR_KEYTYPE_EC
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
        serverThreadCtx.client.keyType = BR_KEYTYPE_RSA
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
      case serverThreadCtx.client.keyType
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
      case serverThreadCtx.client.keyType
      of BR_KEYTYPE_EC:
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

      var v3CtxObj: v3_ext_ctx
      var v3Ctx: X509V3_CTX = addr v3CtxObj
      X509V3_set_ctx(v3Ctx, x509, x509, nil, nil, 0)
      var subjectAltName = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_subject_alt_name, "DNS:localhost".cstring)
      checkErr X509_add_ext(x509, subjectAltName, -1)
      X509_EXTENSION_free(subjectAltName)
      var basicConstraints = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_basic_constraints, "critical,CA:FALSE".cstring)
      checkErr X509_add_ext(x509, basicConstraints, -1)
      X509_EXTENSION_free(basicConstraints)
      var subjectKeyIdentifier = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_subject_key_identifier, "hash".cstring)
      checkErr X509_add_ext(x509, subjectKeyIdentifier, -1)
      X509_EXTENSION_free(subjectKeyIdentifier)
      var authorityKeyIdentifier = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_authority_key_identifier, "keyid:always".cstring)
      checkErr X509_add_ext(x509, authorityKeyIdentifier, -1)
      X509_EXTENSION_free(authorityKeyIdentifier)

      checkErr X509_sign(x509, pkey, EVP_sha1())

      debugBlock:
        checkErr PEM_write_PrivateKey(stdout, pkey, nil, nil, 0, nil, nil)
        checkErr PEM_write_X509(stdout, x509)

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

  proc appListenBase(ctx: ServerThreadCtx, sslFlag: static bool, unixFlag: static bool) {.thread, inline.} =
    let clientSock = ctx.client.sock.accept4(cast[ptr SockAddr](addr ctx.sockAddress), addr ctx.addrLen, O_NONBLOCK)
    if cast[int](clientSock) > 0:
      when cfg.soKeepalive:
        clientSock.setSockOptInt(SOL_SOCKET, SO_KEEPALIVE, 1)
      when cfg.tcpNodelay and not unixFlag:
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

      when sslFlag and cfg.sslLib == BearSSL:
        newClient.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET or EPOLLOUT
      else:
        newClient.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
      let retCtl = epoll_ctl(epfd, EPOLL_CTL_ADD, cast[cint](clientSock), addr newClient.ev)
      if retCtl < 0:
        errorRaise "error: epoll_ctl ret=", retCtl, " errno=", errno

      when cfg.sslLib == SslLib.None:
        if (staticInt(cfg.clientMax) - FreePoolServerUsedCount) - clientFreePool.count >= highGearThreshold:
          if highGearManagerAssigned == 0:
            highGear = true
            for i in 0..<serverWorkerNum:
              discard sem_post(addr throttleBody)

  proc appListen(ctx: ServerThreadCtx) {.thread.} = appListenBase(ctx, false, false)

  proc appListenSsl(ctx: ServerThreadCtx) {.thread.} = appListenBase(ctx, true, false)

  proc appListenUnix(ctx: ServerThreadCtx) {.thread.} = appListenBase(ctx, false, true)

  proc appRoutesSend(ctx: ServerThreadCtx) {.thread.} =
    let client = ctx.client

    acquire(client.spinLock)
    if client.threadId == 0:
      if client.sock == osInvalidSocket:
        release(client.spinLock)
        return
      else:
        client.threadId = ctx.threadId
        release(client.spinLock)
    else:
      client.dirty = ClientDirtyTrue
      release(client.spinLock)
      return

    while true:
      client.dirty = ClientDirtyNone
      let retFlush = client.sendFlush()
      if retFlush == SendResult.Pending:
        acquire(client.spinLock)
        if client.dirty == ClientDirtyNone:
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
        if client.dirty == ClientDirtyNone:
          release(client.spinLock)
          break
        else:
          release(client.spinLock)

    let clientId = client.clientId

    var lastSendErr: SendResult
    proc taskCallback(task: ClientTask): bool =
      lastSendErr = client.send(task.data.toString())
      result = (lastSendErr == SendResult.Success)

    while true:
      client.dirty = ClientDirtyNone
      if clientId.getAndPurgeTasks(taskCallback):
        acquire(client.spinLock)
        if client.dirty == ClientDirtyNone:
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

  proc appRoutesSendSsl(ctx: ServerThreadCtx) {.thread.} =
    echo "appRoutesSendSsl"
    raise

  proc appStream(ctx: ServerThreadCtx) {.thread.} =
    echo "appStream"

  proc appStreamSend(ctx: ServerThreadCtx) {.thread.} =
    echo "appStreamSend"

  var clientHandlerProcs: Array[ClientHandlerProc]

  macro appDummyMacro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add appDummy

  macro appListenMacro(ssl: bool, unix: bool, body: untyped): untyped =
    quote do:
      when `unix`:
        clientHandlerProcs.add appListenUnix
      elif `ssl`:
        clientHandlerProcs.add appListenSsl
      else:
        clientHandlerProcs.add appListen

  proc cmdNodeExists(body: NimNode, cmd: string): bool =
    for n in body:
      if (body.kind == nnkCall or body.kind == nnkCommand) and
        eqIdent(n, cmd) and body.len >= 3:
        return true
      elif cmdNodeExists(n, cmd):
        return true
    return  false

  macro postCmdNodeExists(body: untyped): bool =
    if cmdNodeExists(body, "post"): newLit(true) else: newLit(false)

  proc filterCmdNode(body: var NimNode, filterCmdList: openArray[string], level: int): bool {.discardable.} =
    for i in countdown(body.len - 1, 0):
      var n = body[i]
      if filterCmdNode(n, filterCmdList, level + 1):
        body.del(i)
      if (body.kind == nnkCall or body.kind == nnkCommand):

        if "public" in filterCmdList:
          if eqIdent(body[0], "public") and body[body.len - 1].kind == nnkBlockStmt:
            return true
        if "certificates" in filterCmdList:
          if eqIdent(body[0], "certificates"):
            return true
        if "acme" in filterCmdList:
          if eqIdent(body[0], "acme"):
            return true
        if "proxy" in filterCmdList:
          if eqIdent(body[0], "proxy"):
            return true

        if body.len >= 3:
          for cmd in filterCmdList:
            if eqIdent(body[0], cmd) and body[body.len - 1].kind == nnkStmtList:
              return true
    return false

  proc filterCmdNode(body: NimNode, filterCmdList: openArray[string]): NimNode =
    result = body.copy()
    result.filterCmdNode(filterCmdList, 0)

  macro getRoutesBody(body: untyped): untyped =
    filterCmdNode(body, ["post", "head", "put", "delete", "connect", "options", "trace"])

  macro postRoutesBody(body: untyped): untyped =
    filterCmdNode(body, ["get", "stream", "public", "certificates", "acme", "head", "put", "delete", "connect", "options", "trace"])

  macro fallbackRoutesBody(body: untyped): untyped =
    filterCmdNode(body, ["get", "stream", "public", "certificates", "acme", "post"])

  template routesMainTmpl(body: untyped) {.dirty.} =
    const postCmdExists = postCmdNodeExists(body)
    when postCmdExists:
      proc routesMain(ctx: ServerThreadCtx, client: Client): SendResult {.inline.} =
        getRoutesBody(body)
      proc postRoutesMain(ctx: ServerThreadCtx, client: Client): SendResult {.inline.} =
        template data: ptr UncheckedArray[byte] = ctx.data
        template size: int = ctx.size
        template content: string = ctx.data.toString(ctx.size)
        postRoutesBody(body)
      proc fallbackRoutesMain(ctx: ServerThreadCtx, client: Client): SendResult {.inline.} =
        template data: ptr UncheckedArray[byte] = ctx.data
        template size: int = ctx.size
        template content: string = ctx.data.toString(ctx.size)
        fallbackRoutesBody(body)
    else:
      proc routesMain(ctx: ServerThreadCtx, client: Client): SendResult {.inline.} =
        body
      proc fallbackRoutesMain(ctx: ServerThreadCtx, client: Client): SendResult {.inline.} =
        template data: ptr UncheckedArray[byte] = ctx.data
        template size: int = ctx.size
        template content: string = ctx.data.toString(ctx.size)
        fallbackRoutesBody(body)

  when cfg.sslLib == BearSSL:
    type
      BrEngineState = enum
        SendRec
        RecvRec
        SendApp
        RecvApp

    template brStateDebug(sc: ptr br_ssl_server_context) {.used.} =
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
      clientHandlerProcs.add proc (ctx: ServerThreadCtx) {.thread.} =
        when `ssl`:
          let client = ctx.client

          acquire(client.spinLock)
          if client.threadId == 0:
            if client.sock == osInvalidSocket:
              release(client.spinLock)
              return
            else:
              client.threadId = ctx.threadId
              release(client.spinLock)
          else:
            client.dirty = ClientDirtyTrue
            release(client.spinLock)
            return

          let sock = client.sock

          routesMainTmpl(`body`)

          when cfg.sslLib == BearSSL:
            let ec = addr client.sc.eng
            var bufRecvApp, bufSendRec, bufRecvRec, bufSendApp: ptr UncheckedArray[byte]
            var bufLen {.noinit.}: csize_t
            var headerErr {.noinit.}: int
            var headerNext {.noinit.}: int
            var engine = RecvApp

            block engineBlock:
              while true:
                {.computedGoto.}
                case engine
                of RecvApp:
                  bufRecvApp = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvapp_buf(ec, addr bufLen))
                  if bufRecvApp.isNil:
                    engine = SendRec
                  else:
                    client.addRecvBuf(bufRecvApp, bufLen.int, if bufLen.int > workerRecvBufSize: bufLen.int else: workerRecvBufSize)
                    br_ssl_engine_recvapp_ack(ec, bufLen.csize_t)

                    if client.recvCurSize >= 17 and equalMem(addr client.recvBuf[client.recvCurSize - 4], "\c\L\c\L".cstring, 4):
                      var nextPos = 0
                      var parseSize = client.recvCurSize
                      while true:
                        ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[nextPos])
                        (headerErr, headerNext) = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders, ctx.header)
                        if headerErr == 0:
                          let retMain = routesMain(ctx, client)
                          if client.keepAlive2 == KeepAliveStatus.Unknown:
                            if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                              InternalEssentialHeaderConnection) == "close":
                              client.keepAlive2 = KeepAliveStatus.False
                            else:
                              client.keepAlive2 = KeepAliveStatus.True
                          if retMain == SendResult.Pending or retMain == SendResult.Success:
                            if headerNext < parseSize:
                              nextPos = headerNext
                              parseSize = parseSize - nextPos
                            else:
                              client.recvCurSize = 0
                              engine = SendApp
                              break
                          else:
                            when cfg.errorCloseMode == ErrorCloseMode.UntilConnectionTimeout:
                              if retMain == SendResult.Error:
                                var retCtl = epoll_ctl(epfd, EPOLL_CTL_DEL, cast[cint](client.sock), addr client.ev)
                                if retCtl != 0:
                                  logs.error "error: epoll_ctl EPOLL_CTL_DEL ret=", retCtl, " errno=", errno
                              else:
                                client.close()
                            else:
                              client.close()
                            break engineBlock
                        else:
                          client.close()
                          break engineBlock
                    else:
                      engine = SendRec

                of SendRec:
                  bufSendRec = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendrec_buf(ec, addr bufLen))
                  if bufSendRec.isNil:
                    engine = RecvRec
                  else:
                    while true:
                      let sendlen = sock.send(bufSendRec, bufLen.int, 0.cint)
                      if sendlen > 0:
                        br_ssl_engine_sendrec_ack(ec, sendlen.csize_t)
                        engine = RecvRec
                        break
                      elif sendlen == 0:
                        client.close()
                        break engineBlock
                      else:
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                          acquire(client.spinLock)
                          if client.dirty != ClientDirtyNone:
                            client.dirty = ClientDirtyNone
                            release(client.spinLock)
                            engine = RecvApp
                            break
                          else:
                            client.threadId = 0
                            release(client.spinLock)
                            var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                            if retCtl != 0:
                              logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                            break engineBlock
                        elif errno == EINTR:
                          continue
                        else:
                          client.close()
                          break engineBlock

                of RecvRec:
                  bufRecvRec = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvrec_buf(ec, addr bufLen))
                  if bufRecvRec.isNil:
                    engine = SendApp
                  else:
                    while true:
                      let recvlen = sock.recv(bufRecvRec, bufLen.int, 0.cint)
                      if recvlen > 0:
                        br_ssl_engine_recvrec_ack(ec, recvlen.csize_t)
                        engine = RecvApp
                        break
                      elif recvlen == 0:
                        client.close()
                        break engineBlock
                      else:
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                          engine = SendApp
                          break
                        elif errno == EINTR:
                          continue
                        else:
                          client.close()
                          break engineBlock

                of SendApp:
                  bufSendApp = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendapp_buf(ec, addr bufLen))
                  if bufSendApp.isNil:
                    if bufRecvApp.isNil and bufSendRec.isNil and bufRecvRec.isNil:
                      client.close()
                      break
                    else:
                      engine = RecvApp
                  else:
                    proc taskCallback(task: ClientTask): bool =
                      client.addSendBuf(task.data.toString())
                      result = true
                    discard client.clientId.getAndPurgeTasks(taskCallback)

                    acquire(client.lock)
                    var sendSize = client.sendCurSize
                    if sendSize > 0:
                      if bufLen.int >= sendSize:
                        copyMem(bufSendApp, addr client.sendBuf[0], sendSize)
                        client.sendCurSize = 0
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, sendSize.csize_t)
                        br_ssl_engine_flush(ec, 0)
                      else:
                        copyMem(bufSendApp, client.sendBuf, bufLen.int)
                        client.sendCurSize = sendSize - bufLen.int
                        copyMem(addr client.sendBuf[0], addr client.sendBuf[bufLen], client.sendCurSize)
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, bufLen)
                        br_ssl_engine_flush(ec, 0)
                        engine = SendRec
                    else:
                      release(client.lock)

                      acquire(client.spinLock)
                      if client.dirty != ClientDirtyNone:
                        client.dirty = ClientDirtyNone
                        release(client.spinLock)
                        engine = RecvApp
                      else:
                        if bufRecvApp.isNil and bufSendRec.isNil and
                          not bufRecvRec.isNil and not bufSendApp.isNil and
                          client.sendCurSize == 0:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                        else:
                          release(client.spinLock)
                          engine = RecvApp

          elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
            while true:
              ERR_clear_error()
              let retSslAccept = SSL_accept(client.ssl)
              if retSslAccept < 0:
                client.sslErr = SSL_get_error(client.ssl, retSslAccept)
                debug "SSL_accept err=", client.sslErr, " errno=", errno
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    break
                  else:
                    client.dirty = ClientDirtyNone
                    release(client.spinLock)
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    break
                  else:
                    client.dirty = ClientDirtyNone
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

          template parseHeader4() {.dirty.} =
            var pos = cur + 1
            block parseMain:
              while true:
                if equalMem(cast[pointer](pos), " HTTP/1.".cstring, 8):
                  when cfg.urlRootSafe:
                    if cast[ptr char](cast[pointer](cur))[] != '/':
                      next = -1
                      break
                  ctx.header.url = capbytes.toString(cast[ptr UncheckedArray[byte]](cast[pointer](cur)), pos - cur)
                  inc(pos, 7)
                  if equalMem(cast[pointer](pos), ".1\c\L".cstring, 4):
                    ctx.header.minorVer = 1
                    inc(pos, 2)
                    if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                      next = (pos + 4.uint - cur0).int
                      break
                  elif equalMem(cast[pointer](pos), ".0\c\L".cstring, 4):
                    ctx.header.minorVer = 0
                    inc(pos, 2)
                    if equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4):
                      next = (pos + 4.uint - cur0).int
                      break
                  else:
                    inc(pos)
                    let minorVer = int(cast[ptr char](cast[pointer](pos))[]) - int('0')
                    if minorVer < 0 or minorVer > 9:
                      next = -1
                      break
                    inc(pos)
                    if not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                      next = -1
                      break
                    inc(pos, 2)
                    ctx.header.minorVer = minorVer
                    if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                      next = (pos + 2.uint - cur0).int
                      break

                  var incompleteIdx = 0
                  while true:
                    block paramsLoop:
                      for i in incompleteIdx..<ctx.targetHeaders.len:
                        let (headerId, targetParam) = ctx.targetHeaders[i][]
                        if equalMem(cast[pointer](pos), targetParam.cstring, targetParam.len):
                          inc(pos, targetParam.len)
                          cur = pos
                          while not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                            inc(pos)
                          ctx.header.params[headerId.int] = ((cur - cur0).int, (pos - cur).int)
                          inc(pos, 2)
                          if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                            next = (pos + 2.uint - cur0).int
                            break parseMain
                          if i != incompleteIdx:
                            swap(ctx.targetHeaders[incompleteIdx], ctx.targetHeaders[i])
                          inc(incompleteIdx)
                          if incompleteIdx >= ctx.targetHeaders.len:
                            inc(pos)
                            while(not equalMem(cast[pointer](pos), "\c\L\c\L".cstring, 4)):
                              inc(pos)
                            next = (pos + 4.uint - cur0).int
                            break parseMain
                          break paramsLoop
                      while not equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                        inc(pos)
                      inc(pos, 2)
                      if equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                        next = (pos + 2.uint - cur0).int
                        break parseMain

                elif equalMem(cast[pointer](pos), "\c\L".cstring, 2):
                  next = -1
                  break
                inc(pos)

          if client.recvCurSize == 0:
            while true:
              ctx.recvDataSize = sock.recv(ctx.pRecvBuf0, workerRecvBufSize, 0.cint)

              if ctx.recvDataSize >= 17:
                ctx.nextPos = 0
                ctx.parseSize = ctx.recvDataSize

                block parseBlock:

                  template routesCrLfCheck() {.dirty.} =
                    block findBlock:
                      for i in 0..ctx.parseSize - 5:
                        if equalMem(addr ctx.pRecvBuf[i], "\c\L\c\L".cstring, 4):
                          break findBlock
                      client.addRecvBuf(ctx.pRecvBuf, ctx.parseSize)
                      return

                  template routesMethodBase(requestMethod: static RequestMethod) {.dirty.} =
                    let cur0 {.inject.} = cast[uint](ctx.pRecvBuf)
                    var cur {.inject.} = cur0 + (
                      when requestMethod == RequestMethod.GET: 4
                      elif requestMethod == RequestMethod.POST: 5
                      else:
                        var c: uint
                        block findSpace:
                          for i in 3..7:
                            if ctx.pRecvBuf[i] == cast[byte](' '):
                              ctx.reqMethodPos = 0
                              ctx.reqMethodLen = i
                              c = cast[uint](i) + 1
                              break findSpace
                          client.close()
                          return
                        c)
                    var next {.noInit, inject.}: int
                    parseHeader4()
                    if next >= 0:
                      let retMain = when requestMethod == RequestMethod.GET: routesMain(ctx, client)
                        elif requestMethod == RequestMethod.POST:
                          ctx.size = try:
                            parseInt(getHeaderValue(ctx.pRecvBuf, ctx.header, InternalContentLength))
                          except: 0
                          if ctx.size < 0:
                            client.close()
                            return
                          ctx.data = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[next])
                          inc(next, ctx.size)
                          if next > ctx.parseSize:
                            if next > staticInt(cfg.recvBufExpandBreakSize):
                              client.close()
                              return
                            else:
                              client.addRecvBuf(ctx.pRecvBuf, ctx.parseSize)
                              return
                          when postCmdExists:
                            postRoutesMain(ctx, client)
                          else:
                            fallbackRoutesMain(ctx, client)
                        else:
                          when requestMethod != RequestMethod.Unknown:
                            {.error: $requestMethod & " is not supported.".}
                          when otherRequestMethodExists:
                            ctx.size = try:
                              parseInt(getHeaderValue(ctx.pRecvBuf, ctx.header, InternalContentLength))
                            except: 0
                            if ctx.size < 0:
                              client.close()
                              return
                            ctx.data = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[next])
                            inc(next, ctx.size)
                          else:
                            ctx.size = 0
                          if next > ctx.parseSize:
                            if next > staticInt(cfg.recvBufExpandBreakSize):
                              client.close()
                              return
                            else:
                              client.addRecvBuf(ctx.pRecvBuf, ctx.parseSize)
                              return
                          fallbackRoutesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                          InternalEssentialHeaderConnection) == "close":
                          client.close()
                          return
                        elif next < ctx.parseSize:
                          ctx.nextPos = next
                          ctx.parseSize = ctx.parseSize - ctx.nextPos
                        else:
                          break
                      elif retMain == SendResult.Pending:
                        if next < ctx.parseSize:
                          ctx.nextPos = next
                          ctx.parseSize = ctx.parseSize - ctx.nextPos
                        else:
                          break
                      else:
                        when cfg.errorCloseMode == ErrorCloseMode.UntilConnectionTimeout:
                          if retMain == SendResult.Error:
                            var retCtl = epoll_ctl(epfd, EPOLL_CTL_DEL, cast[cint](client.sock), addr client.ev)
                            if retCtl != 0:
                              logs.error "error: epoll_ctl EPOLL_CTL_DEL ret=", retCtl, " errno=", errno
                          else:
                            client.close()
                        else:
                          client.close()
                        return
                    else:
                      debug "parseHeader4 error"
                      client.close()
                      return

                  if equalMem(addr ctx.pRecvBuf0[ctx.recvDataSize - 4], "\c\L\c\L".cstring, 4):
                    while true:
                      ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[ctx.nextPos])
                      if equalMem(ctx.pRecvBuf, "GET ".cstring, 4):
                        routesMethodBase(RequestMethod.GET)

                      elif equalMem(ctx.pRecvBuf, "POST".cstring, 4):
                        when cfg.postRequestMethod:
                          routesMethodBase(RequestMethod.POST)
                        else:
                          client.close()
                          return
                      else:
                        routesMethodBase(RequestMethod.Unknown)
                  else:
                    while true:
                      ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[ctx.nextPos])
                      if equalMem(ctx.pRecvBuf, "GET ".cstring, 4):
                        routesCrLfCheck()
                        routesMethodBase(RequestMethod.GET)

                      elif equalMem(ctx.pRecvBuf, "POST".cstring, 4):
                        when cfg.postRequestMethod:
                          routesCrLfCheck()
                          routesMethodBase(RequestMethod.POST)
                        else:
                          client.close()
                          return
                      else:
                        routesMethodBase(RequestMethod.Unknown)

              elif ctx.recvDataSize == 0:
                client.close()

              elif ctx.recvDataSize > 0:
                client.addRecvBuf(ctx.pRecvBuf0, ctx.recvDataSize)
                break

              else:
                if errno == EAGAIN or errno == EWOULDBLOCK:
                  return
                elif errno == EINTR:
                  continue
                client.close()
              return

          while true:
            client.reserveRecvBuf(workerRecvBufSize)
            ctx.recvDataSize = sock.recv(addr client.recvBuf[client.recvCurSize], workerRecvBufSize, 0.cint)
            if ctx.recvDataSize > 0:
              client.recvCurSize = client.recvCurSize + ctx.recvDataSize
              if client.recvCurSize >= 17:
                ctx.nextPos = 0
                ctx.parseSize = client.recvCurSize

                block parseBlock:

                  template routesCrLfCheck() {.dirty.} =
                    block findBlock:
                      for i in 0..ctx.parseSize - 5:
                        if equalMem(addr ctx.pRecvBuf[i], "\c\L\c\L".cstring, 4):
                          break findBlock
                      return

                  template routesMethodBase(requestMethod: static RequestMethod) {.dirty.} =
                    let cur0 {.inject.} = cast[uint](ctx.pRecvBuf)
                    var cur {.inject.} = cur0 + (
                      when requestMethod == RequestMethod.GET: 4
                      elif requestMethod == RequestMethod.POST: 5
                      else:
                        var c: uint
                        block findSpace:
                          for i in 3..7:
                            if ctx.pRecvBuf[i] == cast[byte](' '):
                              ctx.reqMethodPos = 0
                              ctx.reqMethodLen = i
                              c = cast[uint](i) + 1
                              break findSpace
                          client.close()
                          return
                        c)
                    var next {.noInit, inject.}: int
                    parseHeader4()
                    if next >= 0:
                      let retMain = when requestMethod == RequestMethod.GET: routesMain(ctx, client)
                        elif requestMethod == RequestMethod.POST:
                          ctx.size = try:
                            parseInt(getHeaderValue(ctx.pRecvBuf, ctx.header, InternalContentLength))
                          except: 0
                          if ctx.size < 0:
                            client.close()
                            return
                          ctx.data = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[next])
                          inc(next, ctx.size)
                          if next > ctx.parseSize:
                            if next > staticInt(cfg.recvBufExpandBreakSize):
                              client.close()
                              return
                            else:
                              return
                          when postCmdExists:
                            postRoutesMain(ctx, client)
                          else:
                            fallbackRoutesMain(ctx, client)
                        else:
                          when requestMethod != RequestMethod.Unknown:
                            {.error: $requestMethod & " is not supported.".}
                          when otherRequestMethodExists:
                            ctx.size = try:
                              parseInt(getHeaderValue(ctx.pRecvBuf, ctx.header, InternalContentLength))
                            except: 0
                            if ctx.size < 0:
                              client.close()
                              return
                            ctx.data = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[next])
                            inc(next, ctx.size)
                          else:
                            ctx.size = 0
                          if next > ctx.parseSize:
                            if next > staticInt(cfg.recvBufExpandBreakSize):
                              client.close()
                              return
                            else:
                              return
                          fallbackRoutesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                          InternalEssentialHeaderConnection) == "close":
                          client.close()
                          return
                        elif next < ctx.parseSize:
                          ctx.nextPos = next
                          ctx.parseSize = ctx.parseSize - ctx.nextPos
                        else:
                          client.recvCurSize = 0
                          break
                      elif retMain == SendResult.Pending:
                        if next < ctx.parseSize:
                          ctx.nextPos = next
                          ctx.parseSize = ctx.parseSize - ctx.nextPos
                        else:
                          client.recvCurSize = 0
                          break
                      else:
                        when cfg.errorCloseMode == ErrorCloseMode.UntilConnectionTimeout:
                          if retMain == SendResult.Error:
                            var retCtl = epoll_ctl(epfd, EPOLL_CTL_DEL, cast[cint](client.sock), addr client.ev)
                            if retCtl != 0:
                              logs.error "error: epoll_ctl EPOLL_CTL_DEL ret=", retCtl, " errno=", errno
                          else:
                            client.close()
                        else:
                          client.close()
                        return
                    else:
                      debug "parseHeader4 error"
                      client.close()
                      return

                  if equalMem(addr client.recvBuf[client.recvCurSize - 4], "\c\L\c\L".cstring, 4):
                    while true:
                      ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[ctx.nextPos])
                      if equalMem(ctx.pRecvBuf, "GET ".cstring, 4):
                        routesMethodBase(RequestMethod.GET)

                      elif equalMem(ctx.pRecvBuf, "POST".cstring, 4):
                        when cfg.postRequestMethod:
                          routesMethodBase(RequestMethod.POST)
                        else:
                          client.close()
                          return
                      else:
                        routesMethodBase(RequestMethod.Unknown)
                  else:
                    while true:
                      ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr client.recvBuf[ctx.nextPos])
                      if equalMem(ctx.pRecvBuf, "GET ".cstring, 4):
                        routesCrLfCheck()
                        routesMethodBase(RequestMethod.GET)

                      elif equalMem(ctx.pRecvBuf, "POST".cstring, 4):
                        when cfg.postRequestMethod:
                          routesCrLfCheck()
                          routesMethodBase(RequestMethod.POST)
                        else:
                          client.close()
                          return
                      else:
                        routesMethodBase(RequestMethod.Unknown)

            elif client.recvCurSize == 0:
              client.close()

            else:
              if errno == EAGAIN or errno == EWOULDBLOCK:
                return
              elif errno == EINTR:
                continue
              client.close()
            return

  macro appRoutesStage1Macro(ssl: bool, body: untyped): untyped {.used.} =
    quote do:
      clientHandlerProcs.add proc (ctx: ServerThreadCtx) {.thread.} =
        let client = ctx.client

        acquire(client.spinLock)
        if client.threadId == 0:
          if client.sock == osInvalidSocket:
            release(client.spinLock)
            return
          else:
            client.threadId = ctx.threadId
            release(client.spinLock)
        else:
          client.dirty = ClientDirtyTrue
          release(client.spinLock)
          return

        let sock = client.sock

        routesMainTmpl(`body`)

        when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
          if client.recvCurSize == 0:
            while true:
              client.dirty = ClientDirtyNone
              ctx.recvDataSize = client.ssl.SSL_read(cast[pointer](ctx.pRecvBuf0), workerRecvBufSize.cint).int
              if ctx.recvDataSize > 0:
                if ctx.recvDataSize >= 17 and equalMem(addr ctx.pRecvBuf0[ctx.recvDataSize - 4], "\c\L\c\L".cstring, 4):
                  var nextPos = 0
                  var parseSize = ctx.recvDataSize
                  while true:
                    ctx.pRecvBuf = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[nextPos])
                    let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders, ctx.header)
                    if retHeader.err == 0:
                      let retMain = routesMain(ctx, client)
                      if retMain == SendResult.Success:
                        if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                          InternalEssentialHeaderConnection) == "close":
                          client.close(ssl = true)
                          return
                        elif retHeader.next < parseSize:
                          nextPos = retHeader.next
                          parseSize = parseSize - nextPos
                        else:
                          break
                      elif retMain == SendResult.Pending:
                        if retHeader.next < parseSize:
                          nextPos = retHeader.next
                          parseSize = parseSize - nextPos
                        else:
                          break
                      else:
                        when cfg.errorCloseMode == ErrorCloseMode.UntilConnectionTimeout:
                          if retMain == SendResult.Error:
                            var retCtl = epoll_ctl(epfd, EPOLL_CTL_DEL, cast[cint](client.sock), addr client.ev)
                            if retCtl != 0:
                              logs.error "error: epoll_ctl EPOLL_CTL_DEL ret=", retCtl, " errno=", errno
                          else:
                            client.close(ssl = true)
                        else:
                          client.close(ssl = true)
                        return
                    else:
                      client.close(ssl = true)
                      return
                else:
                  client.addRecvBuf(ctx.pRecvBuf0, ctx.recvDataSize)
                  break

              elif ctx.recvDataSize == 0:
                client.close(ssl = true)
                return

              else:
                client.sslErr = SSL_get_error(client.ssl, ctx.recvDataSize.cint)
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
                    client.threadId = 0
                    if client.appShift or client.sendCurSize > 0:
                      client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    else:
                      client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                    release(client.spinLock)
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                    break
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                    break
                else:
                  if errno == EAGAIN or errno == EWOULDBLOCK:
                    client.threadId = 0
                    return
                  if client.sslErr == SSL_ERROR_SYSCALL or errno == EINTR:
                    continue
                  client.close(ssl = true)
                  return

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
                  let retHeader = parseHeader(ctx.pRecvBuf, parseSize, ctx.targetHeaders, ctx.header)
                  if retHeader.err == 0:
                    let retMain = routesMain(ctx, client)
                    if retMain == SendResult.Success:
                      if client.keepAlive == true:
                        if ctx.header.minorVer == 0 or getHeaderValue(ctx.pRecvBuf, ctx.header,
                          InternalEssentialHeaderConnection) == "close":
                          client.keepAlive = false
                          client.close(ssl = true)
                          return
                        elif retHeader.next < parseSize:
                          nextPos = retHeader.next
                          parseSize = parseSize - nextPos
                        else:
                          client.recvCurSize = 0
                          break
                      else:
                        client.close(ssl = true)
                        return
                    elif retMain == SendResult.Pending:
                      if retHeader.next < parseSize:
                        nextPos = retHeader.next
                        parseSize = parseSize - nextPos
                      else:
                        client.recvCurSize = 0
                        break
                    else:
                      when cfg.errorCloseMode == ErrorCloseMode.UntilConnectionTimeout:
                        if retMain == SendResult.Error:
                          var retCtl = epoll_ctl(epfd, EPOLL_CTL_DEL, cast[cint](client.sock), addr client.ev)
                          if retCtl != 0:
                            logs.error "error: epoll_ctl EPOLL_CTL_DEL ret=", retCtl, " errno=", errno
                        else:
                          client.close(ssl = true)
                      else:
                        client.close(ssl = true)
                      return
                  else:
                    client.close(ssl = true)
                    return

            elif recvlen == 0:
              client.close(ssl = true)

            else:
              if errno == EAGAIN or errno == EWOULDBLOCK:
                break
              elif errno == EINTR:
                continue
              client.close(ssl = true)
            return

        else:
          raise

  macro appRoutesStage2Macro(ssl: bool, body: untyped): untyped {.used.} =
    quote do:
      clientHandlerProcs.add proc (ctx: ServerThreadCtx) {.thread.} =
        when cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
          let client = ctx.client

          acquire(client.spinLock)
          if client.threadId == 0:
            if client.sock == osInvalidSocket:
              release(client.spinLock)
              return
            else:
              client.threadId = ctx.threadId
              release(client.spinLock)
          else:
            client.dirty = ClientDirtyTrue
            release(client.spinLock)
            return

          while true:
            client.dirty = ClientDirtyNone
            let retFlush = client.sendSslFlush()
            if retFlush == SendResult.Pending:
              acquire(client.spinLock)
              if client.dirty == ClientDirtyNone:
                client.threadId = 0
                release(client.spinLock)
                return
              else:
                release(client.spinLock)
            elif retFlush == SendResult.Error:
              client.close(ssl = true)
              acquire(client.spinLock)
              client.threadId = 0
              release(client.spinLock)
              return
            else:
              acquire(client.spinLock)
              if client.dirty == ClientDirtyNone:
                release(client.spinLock)
                break
              else:
                release(client.spinLock)

          let clientId = client.clientId

          var lastSendErr: SendResult
          proc taskCallback(task: ClientTask): bool =
            lastSendErr = client.send(task.data.toString())
            result = (lastSendErr == SendResult.Success)

          while true:
            client.dirty = ClientDirtyNone
            if clientId.getAndPurgeTasks(taskCallback):
              acquire(client.spinLock)
              if client.dirty == ClientDirtyNone:
                if client.appShift:
                  dec(client.appId)
                  client.appShift = false
                client.threadId = 0
                client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                release(client.spinLock)

                var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                if retCtl != 0:
                  errorRaise "error: appRoutesSend epoll_ctl ret=", retCtl, " ", getErrnoStr()
                return
              else:
                release(client.spinLock)
            else:
              if lastSendErr != SendResult.Pending:
                client.close(ssl = true)
                return

              client.threadId = 0
              return
        else:
          raise

  macro appRoutesSendMacro(ssl: bool, body: untyped): untyped =
    quote do:
      clientHandlerProcs.add appRoutesSend

  template streamMainTmpl(body: untyped) {.dirty.} =
    proc streamMain(client: Client, opcode: WebSocketOpCode,
      data: ptr UncheckedArray[byte], size: int): SendResult =
      body

  template streamMainTmpl(messageBody: untyped, closeBody: untyped) {.dirty.} =
    proc streamMain(client: Client, opcode: WebSocketOpCode,
      data: ptr UncheckedArray[byte], size: int): SendResult =
      template content: string = data.toString(size)
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

  template onProtocol(body: untyped) {.used.} = discard
  template onOpen(body: untyped) {.used.} = discard
  template onMessage(body: untyped) {.used.} = discard
  template onClose(body: untyped) {.used.} = discard

  macro appStreamMacro(ssl: bool, body: untyped): untyped {.used.} =
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
      clientHandlerProcs.add proc (ctx: ServerThreadCtx) {.thread.} =
        when `ssl`:
          when cfg.sslLib == BearSSL:
            debug "stream bearssl"
            let client = ctx.client

            acquire(client.spinLock)
            if client.threadId == 0:
              if client.sock == osInvalidSocket:
                release(client.spinLock)
                return
              else:
                client.threadId = ctx.threadId
                release(client.spinLock)
            else:
              client.dirty = ClientDirtyTrue
              release(client.spinLock)
              return

            let sock = client.sock

            `callStreamMainTmplStmt`

            let ec = addr client.sc.eng
            var bufRecvApp, bufSendRec, bufRecvRec, bufSendApp: ptr UncheckedArray[byte]
            var bufLen {.noinit.}: csize_t
            var engine = RecvApp

            block engineBlock:
              while true:
                {.computedGoto.}
                case engine
                of RecvApp:
                  bufRecvApp = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvapp_buf(ec, addr bufLen))
                  if bufRecvApp.isNil:
                    engine = SendRec
                  else:
                    if client.recvCurSize == 0:
                      client.payloadSize = 0
                    client.addRecvBuf(bufRecvApp, bufLen.int, if bufLen.int > workerRecvBufSize: bufLen.int else: workerRecvBufSize)
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
                  bufSendRec = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendrec_buf(ec, addr bufLen))
                  if bufSendRec.isNil:
                    engine = RecvRec
                  else:
                    while true:
                      let sendlen = sock.send(bufSendRec, bufLen.int, 0.cint)
                      if sendlen > 0:
                        br_ssl_engine_sendrec_ack(ec, sendlen.csize_t)
                        engine = RecvRec
                        break
                      elif sendlen == 0:
                        client.close()
                        break engineBlock
                      else:
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                          acquire(client.spinLock)
                          if client.dirty != ClientDirtyNone:
                            client.dirty = ClientDirtyNone
                            release(client.spinLock)
                            engine = RecvApp
                            break
                          else:
                            client.threadId = 0
                            release(client.spinLock)
                            var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                            if retCtl != 0:
                              logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                            break engineBlock
                        elif errno == EINTR:
                          continue
                        else:
                          client.close()
                          break engineBlock

                of RecvRec:
                  bufRecvRec = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvrec_buf(ec, addr bufLen))
                  if bufRecvRec.isNil:
                    engine = SendApp
                  else:
                    while true:
                      let recvlen = sock.recv(bufRecvRec, bufLen.int, 0.cint)
                      if recvlen > 0:
                        br_ssl_engine_recvrec_ack(ec, recvlen.csize_t)
                        engine = RecvApp
                        break
                      elif recvlen == 0:
                        client.close()
                        break engineBlock
                      else:
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                          engine = SendApp
                          break
                        elif errno == EINTR:
                          continue
                        else:
                          client.close()
                          break engineBlock

                of SendApp:
                  bufSendApp = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendapp_buf(ec, addr bufLen))
                  if bufSendApp.isNil:
                    if bufRecvApp.isNil and bufSendRec.isNil and bufRecvRec.isNil:
                      client.close()
                      break
                    else:
                      engine = RecvApp
                  else:
                    proc taskCallback(task: ClientTask): bool =
                      client.addSendBuf(task.data.toString())
                      result = true
                    discard client.clientId.getAndPurgeTasks(taskCallback)

                    acquire(client.lock)
                    var sendSize = client.sendCurSize
                    if sendSize > 0:
                      if bufLen.int >= sendSize:
                        copyMem(bufSendApp, addr client.sendBuf[0], sendSize)
                        client.sendCurSize = 0
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, sendSize.csize_t)
                        br_ssl_engine_flush(ec, 0)
                      else:
                        copyMem(bufSendApp, client.sendBuf, bufLen.int)
                        client.sendCurSize = sendSize - bufLen.int
                        copyMem(addr client.sendBuf[0], addr client.sendBuf[bufLen], client.sendCurSize)
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, bufLen)
                        br_ssl_engine_flush(ec, 0)
                        engine = SendRec
                    else:
                      release(client.lock)

                      acquire(client.spinLock)
                      if client.dirty != ClientDirtyNone:
                        client.dirty = ClientDirtyNone
                        release(client.spinLock)
                        engine = RecvApp
                      else:
                        if bufRecvApp.isNil and bufSendRec.isNil and
                          not bufRecvRec.isNil and not bufSendApp.isNil and
                          client.sendCurSize == 0:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                        else:
                          release(client.spinLock)
                          engine = RecvApp

          elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
            debug "stream openssl"
            let client = ctx.client

            acquire(client.spinLock)
            if client.threadId == 0:
              if client.sock == osInvalidSocket:
                release(client.spinLock)
                return
              else:
                client.threadId = ctx.threadId
                release(client.spinLock)
            else:
              client.dirty = ClientDirtyTrue
              release(client.spinLock)
              return

            let sock = client.sock

            `callStreamMainTmplStmt`

            if client.recvCurSize == 0:
              while true:
                client.dirty = ClientDirtyNone
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
                        return
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
                  if client.dirty == ClientDirtyNone:
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
                    if client.dirty == ClientDirtyNone:
                      client.threadId = 0
                      if client.appShift or client.sendCurSize > 0:
                        client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                      else:
                        client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                      release(client.spinLock)
                      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                      if retCtl != 0:
                        logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                      return
                    else:
                      release(client.spinLock)
                      break
                  elif client.sslErr == SSL_ERROR_WANT_WRITE:
                    acquire(client.spinLock)
                    if client.dirty == ClientDirtyNone:
                      client.threadId = 0
                      release(client.spinLock)
                      client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                      var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                      if retCtl != 0:
                        logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                      return
                    else:
                      release(client.spinLock)
                      break
                  else:
                    if errno == EINTR:
                      continue
                    client.close(ssl = true)
                    return

            while true:
              client.reserveRecvBuf(workerRecvBufSize)
              client.dirty = ClientDirtyNone
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
                      return
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
                return
              else:
                client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
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
                  if client.dirty == ClientDirtyNone:
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
                  return

        else:
          let client = ctx.client

          acquire(client.spinLock)
          if client.threadId == 0:
            if client.sock == osInvalidSocket:
              release(client.spinLock)
              return
            else:
              client.threadId = ctx.threadId
              release(client.spinLock)
          else:
            client.dirty = ClientDirtyTrue
            release(client.spinLock)
            return

          let sock = client.sock

          `callStreamMainTmplStmt`

          if client.recvCurSize == 0:
            while true:
              client.dirty = ClientDirtyNone
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
                      return
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
                if client.dirty == ClientDirtyNone:
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
                  if client.dirty == ClientDirtyNone:
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
            client.dirty = ClientDirtyNone
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
                    return
                  client.payloadSize = 0
                  client.recvCurSize = 0
                (find, fin, opcode, payload, payloadSize, next, size) = getFrame(next, size)

              if not next.isNil and size > 0:
                copyMem(p, next, size)
                client.recvCurSize = client.payloadSize + size
              else:
                client.recvCurSize = client.payloadSize
            elif recvlen == 0:
              client.close()
              return
            else:
              if errno == EAGAIN or errno == EWOULDBLOCK:
                acquire(client.spinLock)
                if client.dirty == ClientDirtyNone:
                  client.threadId = 0
                  release(client.spinLock)
                  return
                else:
                  release(client.spinLock)
                  continue
              elif errno == EINTR:
                continue
              client.close()
              return

  macro appStreamSendMacro(ssl: bool, body: untyped): untyped {.used.} =
    quote do:
      clientHandlerProcs.add appRoutesSend # appStreamSend is same

  macro appProxyMacro(ssl: bool, body: untyped): untyped {.used.} =
    quote do:
      clientHandlerProcs.add proc (ctx: ServerThreadCtx) {.thread.} =
        let client = ctx.client

        acquire(client.spinLock)
        if client.threadId == 0:
          if client.sock == osInvalidSocket:
            release(client.spinLock)
            return
          else:
            client.threadId = ctx.threadId
            release(client.spinLock)
        else:
          client.dirty = ClientDirtyTrue
          release(client.spinLock)
          return

        let sock = client.sock
        let proxy = client.proxy

        when `ssl`:
          when cfg.sslLib == BearSSL:
            let sc = client.sc
            let ec = addr client.sc.eng
            var bufRecvApp, bufSendRec, bufRecvRec, bufSendApp: ptr UncheckedArray[byte]
            var bufLen {.noinit.}: csize_t
            var headerErr {.noinit.}: int
            var headerNext {.noinit.}: int
            var engine = RecvApp

            block engineBlock:
              while true:
                {.computedGoto.}
                case engine
                of RecvApp:
                  bufRecvApp = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvapp_buf(ec, addr bufLen))
                  if bufRecvApp.isNil:
                    engine = SendRec
                  else:
                    let sendRet = proxy.send(bufRecvApp, bufLen.int)
                    if sendRet == SendResult.Error:
                      client.close(ssl = `ssl`)
                      break
                    br_ssl_engine_recvapp_ack(ec, bufLen.csize_t)

                of SendRec:
                  bufSendRec = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendrec_buf(ec, addr bufLen))
                  if bufSendRec.isNil:
                    engine = RecvRec
                  else:
                    while true:
                      let sendlen = sock.send(bufSendRec, bufLen.int, 0.cint)
                      if sendlen > 0:
                        br_ssl_engine_sendrec_ack(ec, sendlen.csize_t)
                        engine = RecvRec
                        break
                      elif sendlen == 0:
                        client.close()
                        break engineBlock
                      else:
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                          acquire(client.spinLock)
                          if client.dirty != ClientDirtyNone:
                            client.dirty = ClientDirtyNone
                            release(client.spinLock)
                            engine = RecvApp
                            break
                          else:
                            client.threadId = 0
                            release(client.spinLock)
                            var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                            if retCtl != 0:
                              logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                            break engineBlock
                        elif errno == EINTR:
                          continue
                        else:
                          client.close()
                          break engineBlock

                of RecvRec:
                  bufRecvRec = cast[ptr UncheckedArray[byte]](br_ssl_engine_recvrec_buf(ec, addr bufLen))
                  if bufRecvRec.isNil:
                    engine = SendApp
                  else:
                    while true:
                      let recvlen = sock.recv(bufRecvRec, bufLen.int, 0.cint)
                      if recvlen > 0:
                        br_ssl_engine_recvrec_ack(ec, recvlen.csize_t)
                        engine = RecvApp
                        break
                      elif recvlen == 0:
                        client.close()
                        break engineBlock
                      else:
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                          engine = SendApp
                          break
                        elif errno == EINTR:
                          continue
                        else:
                          client.close()
                          break engineBlock

                of SendApp:
                  bufSendApp = cast[ptr UncheckedArray[byte]](br_ssl_engine_sendapp_buf(ec, addr bufLen))
                  if bufSendApp.isNil:
                    if bufRecvApp.isNil and bufSendRec.isNil and bufRecvRec.isNil:
                      client.close()
                      break
                    else:
                      engine = RecvApp
                  else:
                    proc taskCallback(task: ClientTask): bool =
                      client.addSendBuf(task.data.toString())
                      result = true
                    discard client.clientId.getAndPurgeTasks(taskCallback)

                    acquire(client.lock)
                    var sendSize = client.sendCurSize
                    if sendSize > 0:
                      if bufLen.int >= sendSize:
                        copyMem(bufSendApp, addr client.sendBuf[0], sendSize)
                        client.sendCurSize = 0
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, sendSize.csize_t)
                        br_ssl_engine_flush(ec, 0)
                      else:
                        copyMem(bufSendApp, client.sendBuf, bufLen.int)
                        client.sendCurSize = sendSize - bufLen.int
                        copyMem(addr client.sendBuf[0], addr client.sendBuf[bufLen], client.sendCurSize)
                        release(client.lock)
                        br_ssl_engine_sendapp_ack(ec, bufLen)
                        br_ssl_engine_flush(ec, 0)
                        engine = SendRec
                    else:
                      release(client.lock)

                      acquire(client.spinLock)
                      if client.dirty != ClientDirtyNone:
                        client.dirty = ClientDirtyNone
                        release(client.spinLock)
                        engine = RecvApp
                      else:
                        if bufRecvApp.isNil and bufSendRec.isNil and
                          not bufRecvRec.isNil and not bufSendApp.isNil and
                          client.sendCurSize == 0:
                          client.threadId = 0
                          release(client.spinLock)
                          break
                        else:
                          release(client.spinLock)
                          engine = RecvApp

          elif cfg.sslLib == OpenSSL or cfg.sslLib == LibreSSL or cfg.sslLib == BoringSSL:
            while true:
              client.dirty = ClientDirtyNone
              let recvlen = client.ssl.SSL_read(cast[pointer](ctx.pRecvBuf0), workerRecvBufSize.cint).int
              if recvlen > 0:
                let sendRet = proxy.send(ctx.pRecvBuf0, recvlen)
                if sendRet == SendResult.Error:
                  client.close(ssl = `ssl`)
                  break
              elif recvLen == 0:
                client.close(ssl = `ssl`)
                break
              else:
                client.sslErr = SSL_get_error(client.ssl, recvlen.cint)
                if client.sslErr == SSL_ERROR_WANT_READ:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
                    client.threadId = 0
                    if client.appShift or client.sendCurSize > 0:
                      client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    else:
                      client.ev.events = EPOLLIN or EPOLLRDHUP or EPOLLET
                    release(client.spinLock)
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                    break
                elif client.sslErr == SSL_ERROR_WANT_WRITE:
                  acquire(client.spinLock)
                  if client.dirty == ClientDirtyNone:
                    client.threadId = 0
                    release(client.spinLock)
                    client.ev.events = EPOLLRDHUP or EPOLLET or EPOLLOUT
                    var retCtl = epoll_ctl(epfd, EPOLL_CTL_MOD, cast[cint](client.sock), addr client.ev)
                    if retCtl != 0:
                      logs.error "error: epoll_ctl ret=", retCtl, " errno=", errno
                    return
                  else:
                    release(client.spinLock)
                    break
                else:
                  if errno == EAGAIN or errno == EWOULDBLOCK:
                    client.threadId = 0
                    return
                  if client.sslErr == SSL_ERROR_SYSCALL or errno == EINTR:
                    continue
                  client.close(ssl = true)
                  return

        else:
          while true:
            client.dirty = ClientDirtyNone
            let recvlen = sock.recv(ctx.pRecvBuf0, workerRecvBufSize, 0.cint)
            if recvlen > 0:
              let sendRet = proxy.send(ctx.pRecvBuf0, recvlen)
              if sendRet == SendResult.Error:
                client.close(ssl = `ssl`)
                break
            elif recvLen == 0:
              client.close(ssl = `ssl`)
              break
            else:
              if errno == EAGAIN or errno == EWOULDBLOCK:
                acquire(client.spinLock)
                if client.dirty != ClientDirtyNone:
                  release(client.spinLock)
                else:
                  client.threadId = 0
                  release(client.spinLock)
                  break
              elif errno == EINTR:
                continue
              client.close(ssl = `ssl`)
              break

  macro appProxySendMacro(ssl: bool, body: untyped): untyped {.used.} =
    quote do:
      clientHandlerProcs.add appRoutesSend # appProxySend is same

  proc addHandlerProc(name: string, ssl: NimNode, unix: NimNode, body: NimNode): NimNode {.compileTime.} =
    if name == "appListen":
      newCall(name & "Macro", ssl, unix, body)
    else:
      newCall(name & "Macro", ssl, body)

  macro serverHandlerMacro(): untyped =
    result = newStmtList()
    for s in serverHandlerList:
      result.add(addHandlerProc(s[0], s[1], s[2], s[3]))

  serverHandlerMacro()

  macro constAppIdTypeMapMacro(): untyped =
    var bracket = nnkBracket.newTree()
    for t in appIdTypeList:
      bracket.add(newIdentNode($t))
    nnkStmtList.newTree(
      nnkConstSection.newTree(
        nnkConstDef.newTree(
          newIdentNode("appIdTypeMap"),
          newEmptyNode(),
          bracket
        )
      )
    )
  constAppIdTypeMapMacro()

  when cfg.connectionTimeout >= 0:
    proc calcClientConnectionSearchCount(): int {.compileTime.} =
      var countSec = cfg.connectionTimeout div 3
      if countSec == 0:
        countSec = 1
      result = cfg.clientMax div countSec
      if result == 0:
        result = 1

    const clientConnectionSearchCount = calcClientConnectionSearchCount()
    var clientConnectionCheckPos = 0

    proc clientConnectionWhackAMole() =
      for i in 0..clientConnectionSearchCount:
        var client: Client = addr clients[clientConnectionCheckPos]
        if client.sock != osInvalidSocket:
          let appTypeInt = appIdTypeMap[client.appId].int
          if appTypeInt >= AppRoutes.int and appTypeInt <= AppRoutesSend.int:
            if client.dirty == ClientDirtyMole:
              client.close(ssl = true)
            else:
              client.dirty = ClientDirtyMole
        inc(clientConnectionCheckPos)
        if clientConnectionCheckPos >= staticInt(cfg.clientMax):
          clientConnectionCheckPos = 0

  createCertsTable()
  certsTable = unsafeAddr staticCertsTable
  certsIdxTable = unsafeAddr staticCertsIdxTable
  for c in certsTable[].pairs:
    addCertsList(c[0], c[1].idx)

  createCertsFileNameList()

  when cfg.sslLib == BearSSL:
    certKeyChainsList.setLen(staticCertsTable.len + 1)

  when cfg.sslLib != SslLib.None:
    import std/inotify

    var inoty: FileHandle = inotify_init()
    if inoty == -1:
      errorQuit "error: inotify_init err=", errno

    when cfg.sslLib == BearSSL:
      when defined(BEARSSL_DEFAULT_EC):
        certKeyChainsList[0].key = CertPrivateKey(
          keyType: CertPrivateKeyType.EC,
          ec: cast[ptr br_ec_private_key](unsafeAddr EC))
      else:
        certKeyChainsList[0].key = CertPrivateKey(
          keyType: CertPrivateKeyType.RSA,
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

    var checkFolders: seq[string]
    for c in certsTable[].values:
      for _, path in [c.privPath, c.chainPath]:
        let folder = splitPath(path).head
        if not (folder in checkFolders):
          checkFolders.add(folder)
    for folder in checkFolders:
      if not dirExists(folder):
        logs.error "error: certificates path does not exists path=", folder

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
          var wd = inotify_add_watch(inoty, watchFolder.cstring, IN_CLOSE_WRITE or IN_ATTRIB or IN_MOVED_TO)
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
      fds[0].events = posix.POLLIN
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
              if certKeyChains[].key.keyType != CertPrivateKeyType.None:
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
        when cfg.connectionTimeout >= 0:
          clientConnectionWhackAMole()
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
                  certWatchList[i].wd = inotify_add_watch(inoty, watchFolder.cstring, IN_CLOSE_WRITE or IN_ATTRIB or IN_MOVED_TO)
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
        let sitename = $SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
        debug "sitename=", sitename
        let certs = certsTable[][sitename]
        if certs.srvId != serverThreadCtx.client.srvId:
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
    var ctxObj: ServerThreadCtxObj
    serverThreadCtx = cast[ServerThreadCtx](addr ctxObj)
    var ctx = cast[ServerThreadCtx](addr ctxObj)
    ctx.addrLen = sizeof(ctx.sockAddress).SockLen
    ctx.recvBuf = newArray[byte](workerRecvBufSize)
    for i in 0..<TargetHeaders.len:
      ctx.targetHeaders.add(addr TargetHeaders[i])
    ctx.threadId = arg.workerParams.threadId
    ctx.pRecvBuf0 = cast[ptr UncheckedArray[byte]](addr ctx.recvBuf[0])

    serverWorkerInit()

    var events: array[staticInt(cfg.epollEventsSize), EpollEvent]
    var pevents: ptr UncheckedArray[EpollEvent] = cast[ptr UncheckedArray[EpollEvent]](addr events[0])
    var nfd: cint

    when cfg.sslLib != SslLib.None or cfg.connectionPreferred == ConnectionPreferred.InternalConnection:
      while active:
        nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                        staticInt(cfg.epollEventsSize).cint, -1.cint)
        for i in 0..<nfd:
          try:
            ctx.events = pevents[i].events
            ctx.client = cast[Client](pevents[i].data)
            cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
          except:
            let e = getCurrentException()
            logs.error e.name, ": ", e.msg

    else:
      var skip = false

      while active:
        if ctx.threadId == 1:
          nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                          staticInt(cfg.epollEventsSize).cint, -1.cint)
          if not throttleChanged and nfd >= 7:
            throttleChanged = true
            discard sem_post(addr throttleBody)
        else:
          if skip:
            nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                            staticInt(cfg.epollEventsSize).cint, 10.cint)
          else:
            discard sem_wait(addr throttleBody)
            if highGear:
              nfd = 0
            else:
              skip = true
              nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                              staticInt(cfg.epollEventsSize).cint, 0.cint)
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
          var assigned = atomic_fetch_add(addr highGearManagerAssigned, 1, 0)
          if assigned == 0:
            while highGear:
              var nfd = epoll_wait(epfd, cast[ptr EpollEvent](addr events),
                                  staticInt(cfg.epollEventsSize).cint, 1000.cint)
              if nfd > 0:
                var i = 0
                while true:
                  ctx.client = cast[Client](pevents[i].data)
                  if ctx.client.listenFlag:
                    try:
                      cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
                    except:
                      let e = getCurrentException()
                      logs.error e.name, ": ", e.msg
                    if highGear and (staticInt(cfg.clientMax) - FreePoolServerUsedCount) - clientFreePool.count < highGearThreshold:
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
              try:
                cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
              except:
                let e = getCurrentException()
                logs.error e.name, ": ", e.msg

            for i in 0..<serverWorkerNum:
              clientQueue.sendFlush()
            while true:
              if highGearManagerAssigned == 1:
                atomic_fetch_sub(addr highGearManagerAssigned, 1, 0)
                break
              sleep(10)
              clientQueue.sendFlush()

          else:
            while true:
              ctx.client = clientQueue.recv(highGear)
              if ctx.client.isNil: break
              try:
                cast[ClientHandlerProc](clientHandlerProcs[ctx.client.appId])(ctx)
              except:
                let e = getCurrentException()
                logs.error e.name, ": ", e.msg
            atomic_fetch_sub(addr highGearManagerAssigned, 1, 0)

      discard sem_post(addr throttleBody)

template httpTargetHeaderDefault() {.dirty.} =
  when not declared(TargetHeaderParams):
    HttpTargetHeader:
      HeaderHost: "Host"

var serverWaitThread: Thread[WrapperThreadArg]

template serverStart*(wait: bool = true) =
  serverConfigMacro()
  contentsWithCfg(cfg)
  serverMacro()
  when not initServerFlag:
    {.error: "No server block to start.".}
  httpTargetHeaderDefault()
  serverType()
  serverLib(cfg)
  activeHeaderInit()
  startTimeStampUpdater(cfg)

  template serverStartBody() =
    var params: ProxyParams
    params.abortCallback = proc() =
      errorQuit "error: proxy dispatcher"
    var proxyThread = proxyManager(params)

    when cfg.sslLib != SslLib.None:
      var fileWatcherThread: Thread[WrapperThreadArg]
      createThread(fileWatcherThread, threadWrapper, (fileWatcher, ThreadArg(argType: ThreadArgType.Void)))

    let cpuCount = countProcessors()
    when cfg.serverWorkerNum < 0:
      serverWorkerNum = cpuCount
    else:
      serverWorkerNum = staticInt(cfg.serverWorkerNum)
    echo "server workers: ", serverWorkerNum, "/", cpuCount

    highGearThreshold = serverWorkerNum * 3

    var threads = newSeq[Thread[WrapperThreadArg]](serverWorkerNum)
    for i in 0..<serverWorkerNum:
      createThread(threads[i], threadWrapper, (serverWorker,
        ThreadArg(argType: ThreadArgType.WorkerParams, workerParams: (i + 1, workerRecvBufSize))))

    joinThreads(threads)
    for i in countdown(releaseOnQuitEpfds.high, 0):
      let retEpfdClose = releaseOnQuitEpfds[i].close()
      if retEpfdClose != 0:
        logs.error "error: close epfd=", epfd, " ret=", retEpfdClose, " ", getErrnoStr()
    freeClient(staticInt(cfg.clientMax))
    when cfg.sslLib != SslLib.None:
      freeFileWatcher()
      joinThread(fileWatcherThread)
    proxyThread.QuitProxyManager()
    joinThread(contents.timeStampThread)

  when wait:
    serverStartBody()
  else:
    proc waitProc(arg: ThreadArg) {.thread.} =
      serverStartBody()

    createThread(serverWaitThread, threadWrapper, (waitProc, ThreadArg(argType: ThreadArgType.Void)))

template serverWait*() = joinThread(serverWaitThread)

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
