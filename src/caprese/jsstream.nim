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

proc connect0*(stream: Stream; url: cstring; protocols: JsObject; onOpen: proc();
              onReady: proc(); onMessage: proc(data: Uint8Array); onClose: proc()) =
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
      setTimeout(proc() = stream.connect0(url, protocols, onOpen, onReady, onMessage, onClose), ms)

  stream.ws.onerror = proc(evt: JsObject) =
    console.error("websocket error:", evt)

  stream.ws.onopen = proc(evt: JsObject) =
    stream.reconnectCount = RECONNECT_COUNT
    onOpen()
    stream.readyFlag = true
    onReady()

  stream.ws.onclose = proc(evt: JsObject) =
    stream.readyFlag = false
    onClose() # In case of an error, a close event may occur without an open event
    reconnect()

  stream.ws.onmessage = proc(evt: JsObject) =
    var data = newUint8Array(evt.data)
    onMessage(data)

macro connect*(stream: Stream; url: cstring; protocols: JsObject; body: untyped): untyped =
  var onOpen = newStmtList()
  var onReady = newStmtList()
  var onMessage = newStmtList()
  var onClose = newStmtList()
  for b in body:
    if b[0].eqIdent("onOpen"):
      onOpen.add(b[1])
    elif b[0].eqIdent("onReady"):
      onReady.add(b[1])
    elif b[0].eqIdent("onMessage"):
      onMessage.add(b[1])
    elif b[0].eqIdent("onClose"):
      onClose.add(b[1])
  var data = ident"data"
  quote do:
    `stream`.connect0(`url`, `protocols`, proc() = `onOpen`, proc() = `onReady`,
                      proc(`data`: Uint8Array) = `onMessage`, proc() = `onClose`)

macro connect*(stream: Stream; url, protocol: cstring; body: untyped): untyped =
  var protocols = quote do: `protocol`.toJs
  quote do:
    connect(`stream`, `url`, `protocols`, `body`)

macro connect*(stream: Stream; url, protocol: cstring): untyped =
  var protocols = quote do: `protocol`.toJs
  var data = ident"data"
  quote do:
    `stream`.connect0(`url`, `protocols`, proc() = discard, proc() = discard,
                      proc(`data`: Uint8Array) = discard, proc() = discard)

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
