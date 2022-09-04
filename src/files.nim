# Copyright (c) 2021 zenywallet
# nim c -r --forceBuild src/files.nim

import os, strutils, mimetypes
import md5, base64

const DYNAMIC_FILES* = defined(DYNAMIC_FILES)
const DYNAMIC_COMPRESS* = false

when not DYNAMIC_FILES or DYNAMIC_COMPRESS:
  import nimcrypto
  import bytes

when DYNAMIC_COMPRESS:
  import zip/zlib
  import brotli

when not DYNAMIC_FILES:
  import macros, tables

  const srcDir = currentSourcePath().parentDir()
  const publicDir = srcDir / "../public"

  macro constFilesTable: untyped =
    var filesTable: seq[tuple[key: string, val: tuple[content: string, deflate: string,
                                                      brotli: string,
                                                      mime: string,
                                                      sha256: string, md5: string]]]
    let plen = publicDir.len
    let mimes = newMimetypes()
    echo staticExec("nim c -d:release " & (srcDir / "deflate.nim"))
    echo staticExec("nim c -d:release " & (srcDir / "zopfli.nim"))
    echo staticExec("nim c -d:release " & (srcDir / "brotli.nim"))
    for f in walkDirRec(publicDir):
      echo "const file: ", f
      let filename = f[plen..^1]
      let fileSplit = splitFile(filename)
      let data = readFile(f)
      var ext = ""
      if fileSplit.ext.len > 1:
        ext = fileSplit.ext[1..^1]
      let mime = mimes.getMimeType(ext)
      let hash = base64.encode(sha256.digest(data).data)
      let md5 = base64.encode(data.getMD5().toBytesFromHex)
      discard staticExec((srcDir / "deflate") & " " & f & " " & (srcDir / "deflate_tmp"))
      let deflate = readFile(srcDir / "deflate_tmp")
      discard staticExec("rm " & (srcDir / "deflate_tmp"))

      discard staticExec((srcDir / "zopfli") & " " & f & " " & (srcDir / "zopfli_tmp"))
      let zopfli = readFile(srcDir / "zopfli_tmp")
      discard staticExec("rm " & (srcDir / "zopfli_tmp"))

      discard staticExec((srcDir / "brotli") & " " & f & " " & (srcDir / "brotli_tmp"))
      let brotliComp = readFile(srcDir / "brotli_tmp")
      discard staticExec("rm " & (srcDir / "brotli_tmp"))

      echo "deflate : zopfli = ", deflate.len, " : ", zopfli.len
      if deflate.len > zopfli.len:
        filesTable.add((filename, (data, zopfli, brotliComp, mime, hash, md5)))
      else:
        filesTable.add((filename, (data, deflate, brotliComp, mime, hash, md5)))

    newConstStmt(
      newIdentNode("filesTable"),
      newCall("toTable",
        newLit(filesTable)
      )
    )

  constFilesTable()

  proc getConstFile*(file: string): tuple[content: string, deflate: string,
                                          brotli: string,
                                          mime: string,
                                          sha256: string, md5: string] =
    try:
      if file.endsWith("/"):
        result = filesTable[file & "index.html"]
      else:
        result = filesTable[file]
    except KeyError:
      discard

  proc getAcmeChallenge*(file: string): tuple[content: string, mime: string] =
    try:
      if file.startsWith("/.well-known/acme-challenge/"):
        let fileSplit = splitFile(file)
        if fileSplit.dir == "/.well-known/acme-challenge":
          let challengeFile = getCurrentDir() /
                              "public/.well-known/acme-challenge" / fileSplit.name
          let data = readFile(challengeFile)
          let mime = "text/plain"
          result = (data, mime)
    except:
      discard

else:
  var currentPublicDir {.threadvar.}: string
  var mimes {.threadvar.}: MimeDB

  proc initDynamicFile*() =
    currentPublicDir = getCurrentDir() / "public"
    mimes = newMimetypes()

  proc getDynamicFile*(file: string): tuple[content: string, deflate: string,
                                            brotli: string,
                                            mime: string,
                                            sha256: string, md5: string] =
    var requestDir = currentPublicDir / file
    if requestDir.startsWith(currentPublicDir):
      var ext = ""
      if file.endsWith("/"):
        requestDir = requestDir & "index.html"
        ext = "html"
      else:
        let fileSplit = splitFile(file)
        if fileSplit.ext.len > 1:
          ext = fileSplit.ext[1..^1]
      try:
        when DYNAMIC_COMPRESS:
          let data = readFile(requestDir)
          let mime = mimes.getMimeType(ext)
          let hash = base64.encode(sha256.digest(data).data)
          let md5 = base64.encode(data.toMD5())
          let deflate = compress(data, stream = RAW_DEFLATE)
          let brotliComp = brotli.comp(data).toString
          result = (data, deflate, brotliComp, mime, hash, md5)
        else:
          let data = readFile(requestDir)
          let mime = mimes.getMimeType(ext)
          let md5 = base64.encode(data.toMD5())
          result = (data, cast[string](nil), cast[string](nil), mime, cast[string](nil), md5)
      except:
        discard


when isMainModule:
  when not DYNAMIC_FILES:
    echo getConstFile("/")
    echo getConstFile("/index.html")
    echo getConstFile("/index")
  else:
    initDynamicFile()
    echo getDynamicFile("/")
    echo getDynamicFile("/index.html")
    echo getDynamicFile("/index")