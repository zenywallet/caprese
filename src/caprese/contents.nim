# Copyright (c) 2021 zenywallet

import std/macros
import std/os
import std/strutils
import std/mimetypes
import std/times
import exec
import arraylib
import config
export macros except error

var timeStrArrays: array[2, Array[byte]]
var shiftTimeStrArray: int = 0
var pTimeStrArray: ptr Array[byte]
var timeStampThread*: Thread[void]
var activeHeaderStmt* {.compileTime.} = newStmtList()
var curActiveHeaderId* {.compileTime.} = 0
var pActiveHeaderContents*: ptr Array[Array[byte]]
var activeHeaderContents*: array[2, Array[Array[byte]]]
var activeHeaderDatePos*: Array[int]
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

proc updateTimeStamp2() {.inline.} =
  var timeStr = now().utc().format("ddd, dd MMM yyyy HH:mm:ss 'GMT'")
  copyMem(timeStrArrays[shiftTimeStrArray].data, addr timeStr[0], 29)
  pTimeStrArray = addr timeStrArrays[shiftTimeStrArray]
  var a = addr activeHeaderContents[shiftTimeStrArray]
  for i in 0..<a.len:
    copyMem(addr a[i][activeHeaderDatePos[i]], addr timeStr[0], 29)
  pActiveHeaderContents = addr activeHeaderContents[shiftTimeStrArray]
  if shiftTimeStrArray == 0:
    shiftTimeStrArray = 1
  else:
    shiftTimeStrArray = 0

updateTimeStamp()
pActiveHeaderContents = addr activeHeaderContents[0]
shiftTimeStrArray = 1

proc getCurTimeStr*(): string {.inline.} = $cast[cstring](pTimeStrArray[].data)

proc writeTimeStamp*(buf: ptr UncheckedArray[byte]) {.inline.} =
  copyMem(buf, addr pTimeStrArray[].data[0], 25)

proc timeStampUpdater() {.thread.} =
  while active:
    updateTimeStamp()
    sleep(1000)

proc timeStampUpdater2() {.thread.} =
  while active:
    updateTimeStamp2()
    sleep(1000)

proc startTimeStampUpdater*(cfg: static Config) =
  when cfg.headerDate:
    active = true
    if activeHeaderDatePos.len > 0:
      createThread(timeStampThread, timeStampUpdater2)
    else:
      createThread(timeStampThread, timeStampUpdater)
  else:
    discard

proc stopTimeStampUpdater*(waitStop: bool = false) =
  if active:
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

proc getMime2*(mimetype: string): string {.compileTime.} =
  var mimes = newMimetypes()
  var mime = mimes.getMimetype(mimetype, "")
  if mime.len == 0:
    mime = mimes.getExt(mimetype, "")
    if mime.len == 0:
      macros.error "unknown mimetype=" & mimetype
    else:
      mime = mimetype
  mime

template getMime*(mimetype: string): string = mimetype

type
  RawMimeType* = distinct string
  ContentType* = distinct string

template contentsWithCfg*(cfg: static Config) {.dirty.} =
  const HTTP_VERSION* = $cfg.httpVersion
  const ServerName* = cfg.serverName

  template addHeaderBase*(body: string, code: StatusCode, contentType: ContentType): string =
    "HTTP/" & HTTP_VERSION & " " & $code & "\c\L" &
    (when cfg.headerContentType: "Content-Type: " & contentType.string & "\c\L" else: "") &
    (when cfg.headerDate: "Date: " & getCurTimeStr() & "\c\L" else: "") &
    (when cfg.headerServer: "Server: " & ServerName & "\c\L" else: "") &
    "Content-Length: " & $body.len & "\c\L\c\L" &
    body

  template addHeader*(body: string, code: StatusCode, mimetype: string): string =
    addHeaderBase(body, code, getMime(mimetype).ContentType)

  template addHeader*(body: string, code: StatusCode, mimetype: RawMimeType): string =
    addHeaderBase(body, code, mimetype.ContentType)

  template addHeader*(body: string, code: StatusCode, mimetype: string, charset: string): string =
    addHeaderBase(body, code, (getMime(mimetype) & "; charset=" & charset).ContentType)

  template addHeader*(body: string, code: StatusCode, mimetype: RawMimeType, charset: string): string =
    addHeaderBase(body, code, (mimetype.string & "; charset=" & charset).ContentType)

  template addHeader*(body: string, code: StatusCode): string =
    addHeaderBase(body, code, "text/html".ContentType)

  template addHeader*(body: string, mimetype: string | RawMimeType): string =
    addHeader(body, Status200, mimetype)

  template addHeader*(body: string, mimetype: string | RawMimeType, charset: string): string =
    addHeader(body, Status200, mimetype, charset)

  template addHeader*(body: string): string =
    addHeaderBase(body, Status200, "text/html".ContentType)

  type
    EncodingType* {.pure.} = enum
      None = ""
      Deflate = "deflate"
      Brotli = "br"

  template addHeader*(body: string, encodingType: EncodingType, etag: string, code: StatusCode, mimetype: string): string =
    "HTTP/" & HTTP_VERSION & " " & $code & "\c\L" &
    (when cfg.headerContentType: "Content-Type: " & getMime(mimetype) & "\c\L" else: "") &
    "ETag: " & etag & "\c\L" &
    (when encodingType == EncodingType.None: "" else: "Content-Encoding: " & $encodingType & "\c\L") &
    (when cfg.headerDate: "Date: " & getCurTimeStr() & "\c\L" else: "") &
    (when cfg.headerServer: "Server: " & ServerName & "\c\L" else: "") &
    "Content-Length: " & $body.len & "\c\L\c\L" &
    body

  template addHeader*(body: string, encodingType: EncodingType, etag: string, code: StatusCode): string =
    addHeader(body, encodingType, etag, code, "text/html")

  template addHeader*(body: string, encodingType: EncodingType, etag: string): string =
    addHeader(body, encodingType, etag, Status200, "text/html")

  macro activeHeaderBase(body, code, mimetype: static string): Array[byte] =
    when cfg.headerContentType:
      var contentType = getMime2(mimetype)
    var blen = body.len
    var h = "HTTP/" & HTTP_VERSION & " " & code & "\c\L" &
      (when cfg.headerContentType: "Content-Type: " & contentType & "\c\L" else: "") &
      (when cfg.headerDate: "Date: ddd, dd MMM yyyy HH:mm:ss GMT\c\L" else: "") &
      (when cfg.headerServer: "Server: " & ServerName & "\c\L" else: "") &
      "Content-Length: " & $blen & "\c\L\c\L" &
      body

    var last = h.len - blen - 4 - 1
    activeHeaderStmt.add quote do:
      for i in 0..1:
        activeHeaderContents[i].add(cast[Array[byte]](`h`.toArray()))
      activeHeaderDatePos.add(`h`.find("Date: ", 0, `last`) + "Date: ".len)

    var aid = curActiveHeaderId
    inc(curActiveHeaderId)
    quote do:
      pActiveHeaderContents[][`aid`]

  macro activeHeaderBase(body, code: static string, mimetype: static RawMimeType): Array[byte] =
    var blen = body.len
    var h = "HTTP/" & HTTP_VERSION & " " & code & "\c\L" &
      (when cfg.headerContentType: "Content-Type: " & mimetype.string & "\c\L" else: "") &
      (when cfg.headerDate: "Date: ddd, dd MMM yyyy HH:mm:ss GMT\c\L" else: "") &
      (when cfg.headerServer: "Server: " & ServerName & "\c\L" else: "") &
      "Content-Length: " & $blen & "\c\L\c\L" &
      body

    var last = h.len - blen - 4 - 1
    activeHeaderStmt.add quote do:
      for i in 0..1:
        activeHeaderContents[i].add(cast[Array[byte]](`h`.toArray()))
      activeHeaderDatePos.add(`h`.find("Date: ", 0, `last`) + "Date: ".len)

    var aid = curActiveHeaderId
    inc(curActiveHeaderId)
    quote do:
      pActiveHeaderContents[][`aid`]

  macro activeHeaderInit*(): untyped = activeHeaderStmt

  template addActiveHeader*(body: static string, code: static StatusCode, mimetype: static string): Array[byte] =
    activeHeaderBase(body, $code, mimetype)

  template addActiveHeader*(body: static string, mimetype: static string): Array[byte] =
    addActiveHeader(body, Status200, mimetype)

  template addActiveHeader*(body: static string, mimetype: static RawMimeType): Array[byte] =
    activeHeaderBase(body, $Status200, mimetype)

  template addActiveHeader*(body: static string, code: static StatusCode): Array[byte] =
    addActiveHeader(body, code, "text/html")

  template addActiveHeader*(body: static string): Array[byte] =
    addActiveHeader(body, Status200, "text/html")

  when cfg.activeHeader:
    proc addHeader*(body: static string, mimetype: static string = "text/html"): Array[byte] =
      addActiveHeader(body, Status200, mimetype)

  proc redirect301*(location: string): string =
    result = "HTTP/" & HTTP_VERSION & " " & $Status301 & "\c\L" &
            (when cfg.headerContentType: "Content-Type: text/html\c\L" else: "") &
            (when cfg.headerDate: "Date: " & getCurTimeStr() & "\c\L" else: "") &
            (when cfg.headerServer: "Server: " & ServerName & "\c\L" else: "") &
            "Content-Length: 0\c\L" &
            "Location: " & location & "\c\L\c\L"

const BusyBody* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>Sorry, It is a break time.</i>"
const BadRequest* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>Oops, something's wrong?</i>"
const NotFound* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>You just found emptiness.</i>"
const InternalError* = "<!DOCTYPE html><meta charset=\"utf-8\">the fire is dead.<br>the room is freezing."
const TooMany* = "<!DOCTYPE html><meta charset=\"utf-8\"><i>Take your time.</i>"
const Empty* = ""

template addDocType*(body: string): string = "<!DOCTYPE html><meta charset=\"utf-8\">" & body

template convertHtmlDocument*(code: string): string =
  mixin unindent
  let ret = execCode(code).unindent(4)
  echo ret
  ret

proc keepIndent*(code: string): string = ("\n" & code).indent(4)

template staticHtmlDocument*(body: untyped): string =
  when NimVersion == "2.0.4": # workaround modulepaths.nim/getModuleName degrade
    import karax.karaxdsl
    import karax.vdom
  else:
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
    const srcFileDir = splitFile(srcFile).dir

    macro staticScriptMacro(bodyMacro: untyped): string =
      return nnkStmtList.newTree(
        newLit(compileJsCode(srcFileDir, $bodyMacro.toStrLit))
      )
    staticScriptMacro: body

template scriptMinifier*(code, extern: string): string =
  block:
    const srcFile = instantiationInfo(-1, true).filename
    const srcFileDir = splitFile(srcFile).dir

    macro scriptMinifierMacro(): string =
      return nnkStmtList.newTree(
        newLit(minifyJsCode(srcFileDir, code, extern).strip)
      )
    scriptMinifierMacro()

template scriptMinifier*(code: string): string = scriptMinifier(code, "")

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
    const srcFileDir = splitFile(srcFile).dir
    const externCode = generateExternCode(extern)

    macro scriptMinifierMacro(): string =
      return nnkStmtList.newTree(
        newLit(minifyJsCode(srcFileDir, code, externCode).strip)
      )
    scriptMinifierMacro()

#[
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
]#

const saniMap = [
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "&quot;", "", "", "", "&amp;", "&#39;", "", "", "", "", "", "", "", "&#47;",
  "", "", "", "", "", "", "", "", "", "", "", "", "&lt;", "", "&gt;", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "&#96;", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]

#[
{.push checks: off.}
proc sanitizeHtml*(s: string): string =
  for c in s:
    if saniMap[c.byte].len == 0:
      result.add(c)
    else:
      result.add(saniMap[c.byte])
{.pop.}
]#

{.push checks: off.}
proc sanitizeHtml*(s: string): string =
  result = newString(s.len * 6)
  var cur = 0
  var startPos = 0
  for i, c in s:
    if saniMap[c.byte].len != 0:
      let d = i - startPos
      copyMem(addr result[cur], unsafeAddr s[startPos], d)
      inc(cur, d)
      let sLen = saniMap[c.byte].len
      copyMem(addr result[cur], unsafeAddr saniMap[c.byte][0], sLen)
      inc(cur, sLen)
      startPos = i + 1
  let d = s.len - startPos
  copyMem(addr result[cur], unsafeAddr s[startPos], d)
  result.setLen(cur + d)
{.pop.}

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
