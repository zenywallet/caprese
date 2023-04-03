# Copyright (c) 2022 zenywallet

import jsffi
import macros
import asyncjs

type
  DocumentObj* = JsObject
  ConsoleObj* = JsObject
  WindowObj* = JsObject
  JsonObj* = JsObject
  ArgumentsObj* = JsObject
  MathObj* = JsObject
  WebSocketObj*  = JsObject
  Uint8ArrayObj* = JsObject
  Uint32ArrayObj* = JsObject
  NumberObj* = JsObject
  ArrayObj* = JsObject

  WebSocket* = ref object of WebSocketObj
  Uint8Array* = ref object of Uint8ArrayObj
  Uint32Array* = ref object of Uint32ArrayObj
  Number* = ref object of NumberObj
  Array* = ref object of ArrayObj

  JslibError* = object of CatchableError

var document* {.importc, nodecl.}: DocumentObj
var console* {.importc, nodecl.}: ConsoleObj
var window* {.importc, nodecl.}: WindowObj
var JSON* {.importc, nodecl.}: JsonObj
var arguments* {.importc, nodecl.}: ArgumentsObj
var Math* {.importc, nodecl.}: MathObj

{.experimental: "dotOperators".}
macro `.`*(typ: typedesc, field: untyped): JsObject =
  let typeStr = $typ
  let importString = "#." & $field
  result = quote do:
    var staticType {.importc: `typeStr`, nodecl.}: JsObject
    proc helper(o: JsObject): JsObject {.importjs: `importString`, gensym.}
    helper(staticType)

macro `.()`*(typ: typedesc, field: untyped, args: varargs[JsObject, jsFromAst]): JsObject =
  var importString: string
  importString = $typ & "." & $field & "(@)"
  result = quote do:
    proc helper(o: typedesc): JsObject {.importjs: `importString`, gensym, discardable.}
    helper(`typ`)
  for idx in 0 ..< args.len:
    let paramName = newIdentNode("param" & $idx)
    result[0][3].add newIdentDefs(paramName, newIdentNode("JsObject"))
    result[1].add args[idx].copyNimTree

proc newWebSocket*(url, protocols: cstring): WebSocket {.importcpp: "new WebSocket(#, #)".}
proc newUint8Array*(): Uint8Array {.importcpp: "new Uint8Array()".}
proc newUint8Array*(length: int): Uint8Array {.importcpp: "new Uint8Array(#)".}
proc newUint8Array*(obj: JsObject): Uint8Array {.importcpp: "new Uint8Array(#)".} # typedArray, buffer
proc newUint8Array*(buffer: JsObject, byteOffset: int): Uint8Array {.importcpp: "new Uint8Array(#, #)".}
proc newUint8Array*(buffer: JsObject, byteOffset: int, length: int): Uint8Array {.importcpp: "new Uint8Array(#, #, #)".}
proc newUint32Array*(): Uint32Array {.importcpp: "new Uint32Array()".}
proc newUint32Array*(length: int): Uint32Array {.importcpp: "new Uint32Array(#)".}
proc newUint32Array*(obj: JsObject): Uint32Array {.importcpp: "new Uint32Array(#)".} # typedArray, buffer
proc newUint32Array*(buffer: JsObject, byteOffset: int): Uint32Array {.importcpp: "new Uint32Array(#, #)".}
proc newUint32Array*(buffer: JsObject, byteOffset: int, length: int): Uint32Array {.importcpp: "new Uint32Array(#, #, #)".}
proc newTextEncoder*(): JsObject {.importcpp: "new TextEncoder()".}
proc newTextDecoder*(): JsObject {.importcpp: "new TextDecoder()".}
proc newNumber*(val: JsObject): Number {.importcpp: "new Number(#)".}
proc newWorker*(url: cstring): JsObject {.importcpp: "new Worker(#)".}
proc newWorker*(url: cstring, options: JsObject): JsObject {.importcpp: "new Worker(#, #)".}

proc modCall*(module: JsObject, name: cstring, para1: JsObject): JsObject {.importcpp: "#[#](#)", discardable.}

const NumVar* = "number".cstring
const StringVar* = "string".cstring
const ArrayVar* = "array".cstring

proc strToUint8Array*(str: cstring or JsObject): Uint8Array =
  let textenc = newTextEncoder()
  result = (textenc.encode(str)).to(Uint8Array)

proc uint8ArrayToStr*(uint8Array: Uint8Array): cstring =
  let textdec = newTextDecoder()
  result = textdec.decode(uint8Array.toJs).to(cstring)

proc uint8ArrayToStr*(uint8Array: JsObject): cstring =
  let textdec = newTextDecoder()
  result = textdec.decode(uint8Array).to(cstring)

proc match_regexp2(s: cstring): JsObject {.importcpp: "#.match(/.{2}/g)".}

proc hexToUint8Array*(str: cstring or JsObject): Uint8Array =
  if str.toJs.length % 2.toJs != 0.toJs:
    raise newException(JslibError, "no even number")
  newUint8Array(str.match_regexp2().map(proc(b: JsObject): JsObject = Number.parseInt(b, 16)))

proc uint8ArrayToHex*(uint8Array: Uint8Array or JsObject): cstring =
  Array.prototype.map.call(uint8Array, proc(x: JsObject): JsObject = ("00".toJs + (x.toString(16))).slice(-2)).join("").to(cstring)

proc `$`*(uint8Array: Uint8Array): string =
  result = "Uint8Array["
  for i in 0..<uint8Array.length.to(int):
    if i > 0:
      result.add(", " & $uint8Array[i].to(int))
    else:
      result.add($uint8Array[i].to(int))
  result.add("]")

proc setInterval*(cb: proc(), ms: int): int {.importc, discardable.}
proc clearInterval*(intervalId: int) {.importc.}
proc setTimeout*(cb: proc(), ms: int): int {.importc, discardable.}
proc clearTimeout*(timeoutId: int) {.importc.}
proc postMessage*(message: JsObject) {.importc.}

proc sleep_async*(ms: int): Future[void] {.discardable.} =
  return newPromise do (resolve: proc()):
    setTimeout(resolve, ms)

template sleep*(ms: int) = await sleep_async(ms)
