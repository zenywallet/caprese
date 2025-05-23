# Copyright (c) 2022 zenywallet

import os
import macros
import strformat
import strutils

const srcFile = currentSourcePath()
const (srcFileDir, srcFileName, srcFileExt) = splitFile(srcFile)
const binDir = srcFileDir / ".." / "bin"
const cacheDir = srcFileDir / "nimcache"
const execHelperExe = binDir / "exec_helper"
const execHelperSrc = srcFileDir / "exec_helper" & srcFileExt

macro buildExecHelper() =
  echo staticExec("nim c -o:../bin/ " & execHelperSrc)
buildExecHelper()

proc randomStr*(): string {.compileTime.} = staticExec(execHelperExe & " randomstr")

proc rmFile*(filename: string) {.compileTime.} =
  echo staticExec(execHelperExe & " rmfile " & filename)

proc basicExtern*(filename: string): string {.compileTime.} =
  staticExec(execHelperExe & " basicextern " & filename)

proc removeTmpFiles(removeDir: string) {.compileTime.} =
  var tmpFiles = removeDir / srcFileName & "_tmp" & "[[:digit:]]*"
  var ret = staticExec("find " & tmpFiles & " -type f -mmin +60 -print0 2> /dev/null | xargs -r0 rm")
  if ret.len > 0:
    echo ret

proc removeCacheDirs(removeDir: string) {.compileTime.} =
  var tmpFiles = removeDir / srcFileName & "_tmp" & "[[:digit:]]*"
  var ret = staticExec("find \"" & tmpFiles & "\" -type d -mmin +5 -print0 2> /dev/null | xargs -r0 rm -rf")
  if ret.len > 0:
    echo ret

var tmpFileId {.compileTime.}: int = 0

proc execCode*(srcFileDir: string, code: string, rstr: string): string {.compileTime.} =
  inc(tmpFileId)
  let exeFileName = srcFileName & "_tmp" & $tmpFileId & rstr
  let tmpExeFile = srcFileDir / exeFileName
  let tmpSrcFile = tmpExeFile & srcFileExt
  let tmpCacheDir = cacheDir / exeFileName
  writeFile(tmpSrcFile, code)
  echo staticExec("nim c --nimcache:" & tmpCacheDir & " " & tmpSrcFile)
  if not fileExists(tmpExeFile):
    rmFile(tmpSrcFile)
    echo staticExec("rm -rf \"" & tmpCacheDir & "\"")
    macros.error "nim c failed"
  result = staticExec("cd " & srcFileDir & " && " & tmpExeFile)
  removeTmpFiles(srcFileDir)
  removeCacheDirs(cacheDir)
  rmFile(tmpExeFile)
  rmFile(tmpSrcFile)
  echo staticExec("rm -rf \"" & tmpCacheDir & "\"")
  discard staticExec("rmdir \"" & cacheDir & "\"")

template execCode*(code: string): string = execCode(binDir, code, randomStr())

template execCode*(srcFileDir: string, code: string): string = execCode(srcFileDir, code, randomStr())

proc makeDiscardable[T](a: T): T {.discardable, inline.} = a

template staticExecCode*(body: untyped): string = # discardable
  block:
    const srcFile = instantiationInfo(-1, true).filename
    const srcFileDir = splitFile(srcFile).dir

    macro execCodeResult(bodyMacro: untyped): string =
      nnkStmtList.newTree(
        newLit(execCode(srcFileDir, $bodyMacro.toStrLit))
      )
    makeDiscardable(execCodeResult(body))

proc removeThreadVarPatch(code: string): string {.compileTime.} =
  var stage = 0
  for line in splitLines(code):
    if stage == 0 and line.startsWith("if (globalThis.") and line.endsWith(" === undefined) {"):
      stage = 1
    elif stage == 1:
      result.add(line.replace("  globalThis.", "var ") & "\n")
      stage = 2
    elif stage == 2:
      stage = 0
    else:
      result.add(line & "\n")

proc compileJsCode*(srcFileDir: string, code: string, rstr: string): string {.compileTime.} =
  inc(tmpFileId)
  let tmpNameFile = srcFileDir / srcFileName & "_tmp" & $tmpFileId & rstr
  let tmpSrcFile = tmpNameFile & srcFileExt
  let tmpJsFile = tmpNameFile & ".js"
  writeFile(tmpSrcFile, code)
  echo staticExec("nim js -d:release --mm:orc -o:" & tmpJsFile & " " & tmpSrcFile)
  if not fileExists(tmpJsFile):
    rmFile(tmpSrcFile)
    macros.error "nim js failed"
  result = readFile(tmpJsFile)
  result = removeThreadVarPatch(result)
  removeTmpFiles(srcFileDir)
  rmFile(tmpJsFile)
  rmFile(tmpSrcFile)

template compileJsCode*(baseDir, code: string): string =
  compileJsCode(baseDir, code, randomStr())

proc minifyJsCode*(srcFileDir: string, code: string, extern: string, rstr: string): string {.compileTime.} =
  inc(tmpFileId)
  let tmpNameFile = srcFileDir / srcFileName & "_tmp" & $tmpFileId & rstr
  let tmpSrcFile = tmpNameFile & ".js"
  let tmpExtFile = tmpNameFile & "_extern.js"
  let tmpDstFile = tmpNameFile & "_min.js"
  writeFile(tmpSrcFile, code)
  writeFile(tmpExtFile, extern & basicExtern(tmpSrcFile))
  let srcPath = currentSourcePath().parentDir() / ".."
  let downloadClosureCompiler = staticExec fmt"""
if [ -x "$(command -v google-closure-compiler)" ]; then
  echo "download closure-compiler skip"
elif ls "{srcPath}"/closure-compiler-*.jar 1> /dev/null 2>&1; then
  echo "download closure-compiler skip"
else
  mvn dependency:get -e -Ddest="{srcPath}" -Dartifact=com.google.javascript:closure-compiler:LATEST
fi
"""
  echo downloadClosureCompiler
  let closureCompiler = staticExec fmt"""
if [ -x "$(command -v google-closure-compiler)" ]; then
  closure_compiler="google-closure-compiler"
elif ls "{srcPath}"/closure-compiler-*.jar 1> /dev/null 2>&1; then
  closure_compiler="java -jar $(ls "{srcPath}"/closure-compiler-*.jar | sort -r | head -n1)"
fi
echo $closure_compiler
"""
  if closureCompiler.len > 0:
    echo "closure compiler: " & closureCompiler
    let retClosure = staticExec fmt"""
  {closureCompiler} --compilation_level ADVANCED --jscomp_off=checkVars \
  --jscomp_off=checkTypes --jscomp_off=uselessCode --js_output_file="{tmpDstFile}" \
  --externs "{tmpExtFile}" "{tmpSrcFile}" 2>&1 | cut -c 1-240
  """
    if retClosure.len > 0:
      echo retClosure
    result = readFile(tmpDstFile)
    rmFile(tmpDstFile)
  else:
    echo "closure compiler: not found - skip"
    result = code
  removeTmpFiles(srcFileDir)
  rmFile(tmpExtFile)
  rmFile(tmpSrcFile)

template minifyJsCode*(baseDir, code, extern: string): string =
  minifyJsCode(baseDir, code, extern, randomStr())


when isMainModule:
  echo staticExecCode(echo "hello")

  echo staticExecCode(echo "hello!")

  echo compileJsCode(binDir, """
echo "hello!"
""")
