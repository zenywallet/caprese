# Copyright (c) 2021 zenywallet
# nim c -r --forceBuild src/files.nim

import std/os
import std/strutils
import std/macros
import std/tables
import exec

const DYNAMIC_FILES* = defined(DYNAMIC_FILES)
const DYNAMIC_COMPRESS* = false

type FileContent* = object
  content*: string
  deflate*: string
  brotli*: string
  mime*: string
  sha256*: string
  md5*: string

type FileContentErr* = enum
  FileContentSuccess
  FileContentNotFound

type FileContentResult* = object
  case err*: FileContentErr
  of FileContentSuccess:
    data*: FileContent
  of FileContentNotFound:
    discard

const srcDir = currentSourcePath().parentDir()

when DYNAMIC_FILES:
  import std/mimetypes
  import std/base64
  when NimMajor >= 2:
    import checksums/md5
  else:
    import std/md5

  when DYNAMIC_COMPRESS:
    import zip/zlib
    import brotli

  var currentPublicDirString*: string
  var currentPublicDir*: cstring

  type
    MimeDB2 = object
      mimes: OrderedTable[string, string]

  func getMimetype(mimedb: MimeDB2, ext: string, default = "text/plain"): string =
    if ext.startsWith("."):
      result = mimedb.mimes.getOrDefault(ext.toLowerAscii.substr(1))
    else:
      result = mimedb.mimes.getOrDefault(ext.toLowerAscii())
    if result == "":
      return default

  const mimes = MimeDB2(mimes: mimetypes.mimes.toOrderedTable())

  proc initDynamicFile*(publicPath: string = "public") =
    echo "warning: Dynamic file loading is for test purposes only. Super slow."
    if publicPath.startsWith("/"):
      currentPublicDirString = publicPath
    else:
      currentPublicDirString = getCurrentDir() / publicPath
    currentPublicDir = currentPublicDirString.cstring
    echo "public: ", currentPublicDirString

  proc getDynamicFile*(file: string): FileContentResult =
    var currentPublicDir = $currentPublicDir
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
          let hash = "\"" & base64.encode(sha256.digest(data).data) & "\""
          let md5 = "\"" & base64.encode(data.toMD5()) & "\""
          let deflate = compress(data, stream = RAW_DEFLATE)
          let brotliComp = brotli.comp(data).toString
          result = FileContentResult(err: FileContentSuccess, data: FileContent(content: data,
            deflate: deflate, brotli: brotliComp, mime: mime, sha256: hash, md5: md5))
        else:
          let data = readFile(requestDir)
          let mime = mimes.getMimeType(ext)
          let md5 = "\"" & base64.encode(data.toMD5()) & "\""
          result = FileContentResult(err: FileContentSuccess, data: FileContent(content: data,
            deflate: cast[string](""), brotli: cast[string](""), mime: mime,
            sha256: cast[string](""), md5: md5))
      except:
        result = FileContentResult(err: FileContentNotFound)

proc getAcmeChallenge*(path, file: string): tuple[acmeFlag: bool, content: string, mime: string] =
  if file.startsWith("/.well-known/acme-challenge/"):
    let fileSplit = splitFile(file)
    if fileSplit.dir == "/.well-known/acme-challenge":
      let challengeFile = path / ".well-known/acme-challenge" / fileSplit.name
      try:
        let data = readFile(challengeFile)
        let mime = "text/plain"
        result = (true, data, mime)
      except:
        result = (true, "", "")
    else:
      result = (true, "", "")

var buildToolFlag {.compileTime.} = false
macro buildCompressTools() =
  if not buildToolFlag:
    buildToolFlag = true
    echo staticExec("nim c -d:release --threads:on -o:../bin/ " & (srcDir / "files_helper.nim"))

var tmpFileId {.compileTime.}: int = 0

macro createStaticFilesTable*(importPath: string): untyped =
  buildCompressTools()
  var path = getProjectPath() / $importPath
  echo "createStaticFilesTable: ", path
  inc(tmpFileId)
  let tmpFile = srcDir / ".." / "bin/files_helper_tmp" & $tmpFileId & randomStr()
  echo staticExec((srcDir / ".." / "bin/files_helper") & " import " & path & " " & tmpFile)
  var dump = readFile(tmpFile)
  discard staticExec("rm " & tmpFile)
  var last = dump.len
  var pos = 0
  var filesTable: seq[tuple[key: string, val: FileContent]]
  var datas: array[7, string]
  var itemId = 0
  while pos + 8 < last:
    var size = 0
    for i in 0..7:
      size = dump[pos + 7 - i].int + (size shl 8)
    pos = pos + 8
    datas[itemId] = dump[pos..<pos+size]
    pos = pos + size
    inc(itemId)
    if itemId > 6:
      filesTable.add((datas[0], FileContent(content: datas[1],
                      deflate: datas[2], brotli: datas[3],
                      mime: datas[4], sha256: datas[5], md5: datas[6])))
      echo datas[0], " ", datas[4], " ", datas[1].len, " ", datas[2].len, " ", datas[3].len
      itemId = 0
  newCall("toTable", newLit(filesTable))

proc getStaticFile*(filesTable: Table[string, FileContent], file: string): FileContentResult =
  try:
    if file.endsWith("/"):
      result = FileContentResult(err: FileContentSuccess, data: filesTable[file & "index.html"])
    else:
      result = FileContentResult(err: FileContentSuccess, data: filesTable[file])
  except KeyError:
    result = FileContentResult(err: FileContentNotFound)

proc createStaticFile*(content: string, ext: string): FileContent {.compileTime.} =
  buildCompressTools()
  inc(tmpFileId)
  let tmpInFile = srcDir / ".." / "bin/files_helper_tmp" & $tmpFileId & randomStr()
  inc(tmpFileId)
  let tmpOutFile = srcDir / ".." / "bin/files_helper_tmp" & $tmpFileId & randomStr()
  writeFile(tmpInFile, content)
  echo staticExec((srcDir / ".." / "bin/files_helper") & " single " & tmpInFile & " " & ext & " " & tmpOutFile)
  var dump = readFile(tmpOutFile)
  discard staticExec("rm " & tmpOutFile)
  discard staticExec("rm " & tmpInFile)
  var last = dump.len
  var pos = 0
  var filesTable: seq[tuple[key: string, val: FileContent]]
  var datas: array[7, string]
  var itemId = 0
  while pos + 8 < last:
    var size = 0
    for i in 0..7:
      size = dump[pos + 7 - i].int + (size shl 8)
    pos = pos + 8
    datas[itemId] = dump[pos..<pos+size]
    pos = pos + size
    inc(itemId)
    if itemId > 6:
      filesTable.add((datas[0], FileContent(content: datas[1],
                      deflate: datas[2], brotli: datas[3],
                      mime: datas[4], sha256: datas[5], md5: datas[6])))
      echo datas[0], " ", datas[4], " ", datas[1].len, " ", datas[2].len, " ", datas[3].len
      itemId = 0
  filesTable[0].val


when isMainModule:
  when DYNAMIC_FILES:
    initDynamicFile()
    echo getDynamicFile("/")
    echo getDynamicFile("/index.html")
    echo getDynamicFile("/index")

  const filesTable1 = createStaticFilesTable(importPath = "../www/YOUR_DOMAIN_1")
  const filesTable2 = createStaticFilesTable(importPath = "../www/YOUR_DOMAIN_2")
