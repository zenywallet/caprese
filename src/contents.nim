# Copyright (c) 2021 zenywallet

import statuscode
import macros
import os
import strutils
import exec
import mimetypes
export macros except error
import times
import arraylib
import config

var cfg {.compileTime.}: Config = defaultConfig()

template loadConfig(cfg: static Config) {.dirty.} =
  const HTTP_VERSION* = $cfg.httpVersion
  const ServerName* = cfg.serverName

loadConfig(cfg)

var timeStrArrays: array[2, Array[byte]]
var shiftTimeStrArray: int = 0
var pTimeStrArray: ptr Array[byte]
var timeStampThread*: Thread[void]
var active = false

for i in 0..1:
  timeStrArrays[i].newArray(30)

proc updateTimeStamp() {.inline.} =
  var timeStr = now().utc().format("ddd, dd MMM yyyy HH:mm:ss 'GMT'")
  copyMem(timeStrArrays[shiftTimeStrArray].data, addr timeStr[0], 29)
  pTimeStrArray = addr timeStrArrays[shiftTimeStrArray]
  if shiftTimeStrArray == 0:
    shiftTimeStrArray = 1
  else:
    shiftTimeStrArray = 0

updateTimeStamp()

proc getCurTimeStr*(): string {.inline.} = $cast[cstring](pTimeStrArray[].data)

proc writeTimeStamp*(buf: ptr UncheckedArray[byte]) {.inline.} =
  copyMem(buf, addr pTimeStrArray[].data[0], 25)

proc timeStampUpdater() {.thread.} =
  while active:
    updateTimeStamp()
    sleep(1000)

proc startTimeStampUpdater*() =
  active = true
  createThread(timeStampThread, timeStampUpdater)

proc stopTimeStampUpdater*(waitStop: bool = false) =
  active = false
  if waitStop:
    joinThread(timeStampThread)

macro getMime*(mimetype: static string): untyped =
  var mimeStr = $mimetype
  var mimes = newMimetypes()
  var mime = mimes.getMimetype(mimeStr, "")
  if mime.len == 0:
    mime = mimes.getExt(mimeStr, "")
    if mime.len == 0:
      macros.error "unknown mimetype=" & mimeStr
    else:
      mime = mimeStr
  newLit(mime)

template getMime*(mimetype: string): string = mimetype

template addHeader*(body: string, code: StatusCode, mimetype: string = "text/html"): string =
  "HTTP/" & HTTP_VERSION & " " & $code & "\c\L" &
  "Content-Type: " & getMime(mimetype) & "\c\L" &
  "Date: " & getCurTimeStr() & "\c\L" &
  "Server: " & ServerName & "\c\L" &
  "Content-Length: " & $body.len & "\c\L\c\L" &
  body

template addHeader*(body: string, mimetype: string): string = addHeader(body, Status200, mimetype)

template addHeader*(body: string): string = addHeader(body, Status200, "text/html")

type
  EncodingType* {.pure.} = enum
    None = ""
    Deflate = "deflate"
    Brotli = "br"

template addHeader*(body: string, encodingType: EncodingType, etag: string, code: StatusCode, mimetype: string): string =
  "HTTP/" & HTTP_VERSION & " " & $code & "\c\L" &
  "Content-Type: " & getMime(mimetype) & "\c\L" &
  "ETag: " & etag & "\c\L" &
  (when encodingType == EncodingType.None: "" else: "Content-Encoding: " & $encodingType & "\c\L") &
  "Date: " & getCurTimeStr() & "\c\L" &
  "Server: " & ServerName & "\c\L" &
  "Content-Length: " & $body.len & "\c\L\c\L" &
  body

template addHeader*(body: string, encodingType: EncodingType, etag: string, code: StatusCode): string =
  addHeader(body, encodingType, etag, code, "text/html")

template addHeader*(body: string, encodingType: EncodingType, etag: string): string =
  addHeader(body, encodingType, etag, Status200, "text/html")

proc redirect301*(location: string): string =
  result = "HTTP/" & HTTP_VERSION & " " & $Status301 & "\c\L" &
          "Content-Type: text/html\c\L" &
          "Date: " & getCurTimeStr() & "\c\L" &
          "Server: " & ServerName & "\c\L" &
          "Content-Length: 0\c\L" &
          "Location: " & location & "\c\L\c\L"

const BusyBody* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>Sorry, It is a break time.</i>"
const BadRequest* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>Oops, something's wrong?</i>"
const NotFound* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>You just found emptiness.</i>"
const InternalError* = "<!DOCTYPE html><meta charset=\"utf-8\">the fire is dead.<br>the room is freezing."
const TooMany* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>Take your time.</i>"
const Empty* = ""

template addDocType*(body: string): string = "<!DOCTYPE html><meta charset=\"utf-8\">" & body

const srcFile = currentSourcePath()
const (srcFileDir, srcFieName, srcFileExt) = splitFile(srcFile)

var tmpFileId {.compileTime.}: int = 0

template convertHtmlDocument*(code: string): string =
  mixin unindent
  let ret = execCode(code).unindent(4)
  echo ret
  ret

proc keepIndent*(code: string): string = ("\n" & code).indent(4)

template staticHtmlDocument*(body: untyped): string =
  import karax/[karaxdsl, vdom]
  block:
    macro staticHtmlDocumentMacro(): string =
      var code = "import re\n" &
        "let content = \"\"\"" & $body & "\"\"\"\n" &
        """echo "<!DOCTYPE html>\n" & content.replacef(re"<([^>]*) />", "<$1>")""" & "\n"
      nnkStmtList.newTree(
        newLit(convertHtmlDocument(code))
      )
    staticHtmlDocumentMacro()

template staticScript*(body: untyped): string =
  block:
    const srcFile = instantiationInfo(-1, true).filename
    const (srcFileDir, srcFieName, srcFileExt) = splitFile(srcFile)

    macro staticScriptMacro(bodyMacro: untyped): string =
      return nnkStmtList.newTree(
        newLit(compileJsCode(srcFileDir, $bodyMacro.toStrLit))
      )
    staticScriptMacro: body

template scriptMinifier*(code, extern: string): string =
  block:
    const srcFile = instantiationInfo(-1, true).filename
    const (srcFileDir, srcFieName, srcFileExt) = splitFile(srcFile)

    macro scriptMinifierMacro(): string =
      return nnkStmtList.newTree(
        newLit(minifyJsCode(srcFileDir, code, extern))
      )
    scriptMinifierMacro()

var externKeywordId {.compileTime.}: int

proc generateExternCode(externKeyword: seq[string]): string {.compileTime.} =
  inc(externKeywordId)
  result = "var externKeyword" & $externKeywordId & " = {\n"
  for i, s in externKeyword:
    if s.len == 0:
      error "scriptMinifier extern keyword length = 0"
    if i == externKeyword.len - 1:
      result.add("  " & s & ": 0\n")
    else:
      result.add("  " & s & ": 0,\n")
  result.add("};\n")

template scriptMinifier*(code: string, extern: seq[string]): string =
  block:
    const srcFile = instantiationInfo(-1, true).filename
    const (srcFileDir, srcFieName, srcFileExt) = splitFile(srcFile)
    const externCode = generateExternCode(extern)

    macro scriptMinifierMacro(): string =
      return nnkStmtList.newTree(
        newLit(minifyJsCode(srcFileDir, code, externCode))
      )
    scriptMinifierMacro()

proc sanitizeHtml*(s: string): string =
  for c in s:
    case c
    of '&': result.add("&amp;")
    of '\'': result.add("&#39;")
    of '`': result.add("&#96;")
    of '"': result.add("&quot;")
    of '<': result.add("&lt;")
    of '>': result.add("&gt;")
    of '/': result.add("&#47;")
    else: result.add(c)

template mimeType*(mime: string): string =
  mixin newMimetypes, getMimetype
  block:
    macro mimeTypeMacro(): string =
      var m = newMimetypes()
      var mstr = m.getMimetype(mime)
      return nnkStmtList.newTree(
        newLit(mstr)
      )
    mimeTypeMacro()
