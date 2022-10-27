# Copyright (c) 2021 zenywallet

import statuscode

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
