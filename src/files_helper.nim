# Copyright (c) 2023 zenywallet

import std/os
import std/osproc
import std/locks
import std/mimetypes
import std/md5
import std/base64
import nimcrypto
import zopfli
import brotli
import queue
import bytes

if paramCount() == 2:
  let importPath = paramStr(1)
  let outFileName = paramStr(2)
  let pathLen = importPath.len
  var files: seq[string]
  for f in walkDirRec(importPath):
    files.add(f)
  var queue = newQueue[ptr UncheckedArray[byte]](files.len)
  for f in files:
    var p = cast[ptr UncheckedArray[byte]](allocShared0(f.len + 1))
    copyMem(p, unsafeAddr f[0], f.len)
    queue.add(p)

  var lock: Lock
  initLock(lock)

  var outFile: File
  var ret = open(outFile, outFileName, FileMode.fmWrite)
  if not ret:
    echo "error: open ", outFileName
    quit(QuitFailure)
  var writeError = false

  proc worker() {.thread.} =
    let mimes = newMimetypes()
    while true:
      let p = queue.pop()
      if p.isNil:
        break
      let f = $cast[cstring](p)
      let filename = f[pathLen..^1]
      let fileSplit = splitFile(filename)
      let content = readFile(f)
      var ext = ""
      if fileSplit.ext.len > 1:
        ext = fileSplit.ext[1..^1]
      let mime = mimes.getMimeType(ext)
      let hash = base64.encode(sha256.digest(content).data)
      let md5 = base64.encode(content.getMD5().toBytesFromHex)
      var zopfliComp, brotliComp: seq[byte]
      if content.len > 0:
        try:
          zopfliComp = zopfli.comp(content)
        except:
          echo "error: zopfli comp"
        try:
          brotliComp = brotli.comp(content)
        except:
          echo "error: brotli comp"
      let dump = (filename.len, filename,
                  content.len, content,
                  zopfliComp.len, zopfliComp,
                  brotliComp.len, brotliComp,
                  mime.len, mime,
                  hash.len, hash,
                  md5.len, md5).toBytes
      acquire(lock)
      let retLen = outFile.writeBuffer(unsafeAddr dump[0], dump.len)
      #echo filename, " ", mime, " ", content.len, " ", zopfliComp.len, " ", brotliComp.len
      release(lock)
      if retLen != dump.len:
        writeError = true
        break
  let cpuCount = countProcessors()
  var threads = newSeq[Thread[void]](cpuCount)
  for i in 0..<cpuCount:
    createThread(threads[i], worker)
  joinThreads(threads)
  outFile.close()
  if writeError:
    echo "error: write ", outFileName
    quit(QuitFailure)
