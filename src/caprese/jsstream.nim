# Copyright (c) 2023 zenywallet

import std/jsffi except `&`
import std/asyncjs
import std/macros
import jslib

const RECONNECT_COUNT = 120
const RECONNECT_WAIT = 15000
const RECONNECT_INFINITE = true

type
  StreamObj* = object
    ws: JsObject
    readyFlag: bool
    reconnectCount: int

  Stream* = ref StreamObj

proc newStream*(): Stream = new StreamObj

proc connect0*(stream: Stream; url: cstring; protocols: JsObject; onOpen: proc(evt: JsObject);
              onReady: proc(evt: JsObject); onMessage: proc(evt: JsObject, data: Uint8Array);
              onClose: proc(evt: JsObject); onError: proc(evt: JsObject)) =
  stream.ws = newWebSocket(url, protocols)
  stream.ws.binaryType = "arraybuffer".cstring
  when RECONNECT_INFINITE:
    if stream.reconnectCount == 0:
      stream.reconnectCount = RECONNECT_COUNT

  template reconnect() {.dirty.} =
    if stream.reconnectCount > 0:
      dec(stream.reconnectCount)
      let randomWait = Math.round(Math.random() * (RECONNECT_WAIT * 2 / 3).toJs).to(int)
      let ms = Math.round(RECONNECT_WAIT / 3).to(int) + randomWait
      setTimeout(proc() = stream.connect0(url, protocols, onOpen, onReady, onMessage, onClose, onError), ms)

  stream.ws.onerror = proc(evt: JsObject) = onError(evt)

  stream.ws.onopen = proc(evt: JsObject) =
    stream.reconnectCount = RECONNECT_COUNT
    onOpen(evt)
    stream.readyFlag = true
    onReady(evt)

  stream.ws.onclose = proc(evt: JsObject) =
    stream.readyFlag = false
    onClose(evt) # In case of an error, a close event may occur without an open event
    reconnect()

  stream.ws.onmessage = proc(evt: JsObject) =
    var data = newUint8Array(evt.data)
    onMessage(evt, data)

macro connect*(stream: Stream; url: cstring; protocols: JsObject; body: untyped): untyped =
  var onOpen = newStmtList()
  var onReady = newStmtList()
  var onMessage = newStmtList()
  var onClose = newStmtList()
  var onError = newStmtList()
  for b in body:
    if b[0].eqIdent("onOpen"):
      onOpen.add(b[1])
    elif b[0].eqIdent("onReady"):
      onReady.add(b[1])
    elif b[0].eqIdent("onMessage"):
      onMessage.add(b[1])
    elif b[0].eqIdent("onClose"):
      onClose.add(b[1])
    elif b[0].eqIdent("onError"):
      onError.add(b[1])
  var evt = ident"evt"
  var data = ident"data"
  quote do:
    `stream`.connect0(`url`, `protocols`,
                      proc(`evt`: JsObject) = `onOpen`,
                      proc(`evt`: JsObject) = `onReady`,
                      proc(`evt`: JsObject, `data`: Uint8Array) = `onMessage`,
                      proc(`evt`: JsObject) = `onClose`,
                      proc(`evt`: JsObject) = `onError`)

macro connect*(stream: Stream; url, protocol: cstring; body: untyped): untyped =
  var protocols = quote do: `protocol`.toJs
  quote do:
    connect(`stream`, `url`, `protocols`, `body`)

macro connect*(stream: Stream; url, protocol: cstring): untyped =
  var protocols = quote do: `protocol`.toJs
  var evt = ident"evt"
  var data = ident"data"
  quote do:
    `stream`.connect0(`url`, `protocols`,
                      proc(`evt`: JsObject) = discard,
                      proc(`evt`: JsObject) = discard,
                      proc(`evt`: JsObject, `data`: Uint8Array) = discard,
                      proc(`evt`: JsObject) = discard,
                      proc(`evt`: JsObject) = discard)

proc close*(stream: Stream) =
  if not stream.ws.isNil:
    stream.reconnectCount = 0
    stream.ws.close()
    stream.ws = jsNull

proc send*(stream: Stream; data: Uint8Array): bool {.discardable.} =
  if stream.ws.readyState == WebSocket.OPEN:
    stream.ws.send(data)

template ready*(stream: Stream; body: untyped) =
  block ready:
    proc bodyMain() {.async, discardable.} =
      while not stream.readyFlag:
        sleep(100)
      body
    bodyMain()
