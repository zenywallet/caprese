# Copyright (c) 2021 zenywallet

import statuscode
import macros
import os
import strutils
import exec
import mimetypes
export macros except error

const HTTP_VERSION* = 1.1

proc addHeader*(body: string, code: StatusCode = Status200, mimetype: string = "text/html"): string =
  result = "HTTP/" & $HTTP_VERSION & " " & $code & "\c\L" &
          "Content-Type: " & mimetype & "\c\L" &
          "Content-Length: " & $body.len & "\c\L\c\L" &
          body

proc addHeader*(body: string, etag: string, code: StatusCode = Status200, mimetype: string = "text/html"): string =
  result = "HTTP/" & $HTTP_VERSION & " " & $code & "\c\L" &
          "Content-Type: " & mimetype & "\c\L" &
          "ETag: " & etag & "\c\L" &
          "Content-Length: " & $body.len & "\c\L\c\L" &
          body

proc addHeaderDeflate*(body: string, etag: string, code: StatusCode = Status200, mimetype: string = "text/html"): string =
  result = "HTTP/" & $HTTP_VERSION & " " & $code & "\c\L" &
          "Content-Type: " & mimetype & "\c\L" &
          "ETag: " & etag & "\c\L" &
          "Content-Encoding: deflate\c\L" &
          "Content-Length: " & $body.len & "\c\L\c\L" &
          body

proc addHeaderBrotli*(body: string, etag: string, code: StatusCode = Status200, mimetype: string = "text/html"): string =
  result = "HTTP/" & $HTTP_VERSION & " " & $code & "\c\L" &
          "Content-Type: " & mimetype & "\c\L" &
          "ETag: " & etag & "\c\L" &
          "Content-Encoding: br\c\L" &
          "Content-Length: " & $body.len & "\c\L\c\L" &
          body

proc redirect301*(location: string): string =
  result = "HTTP/" & $HTTP_VERSION & " " & $Status301 & "\c\L" &
          "Content-Type: text/html\c\L" &
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
