# Copyright (c) 2022 zenywallet

import os
import macros
import strformat
import strutils

const srcFile = currentSourcePath()
const (srcFileDir, srcFileName, srcFileExt) = splitFile(srcFile)
const binDir = srcFileDir / "bin"
const execHelperExe = binDir / "exec_helper"
const execHelperSrc = srcFileDir / "exec_helper" & srcFileExt

macro buildExecHelper() =
  echo staticExec("nim c -o:bin/ " & execHelperSrc)
buildExecHelper()

proc randomStr*(): string {.compileTime.} = staticExec(execHelperExe & " randomstr")

proc rmFile*(filename: string) {.compileTime.} =
  echo staticExec(execHelperExe & " rmfile " & filename)

proc basicExtern*(filename: string): string {.compileTime.} =
  staticExec(execHelperExe & " basicextern " & filename)

proc removeTmpFiles(removeDir: string) {.compileTime.} =
  var tmpFiles = removeDir / srcFileName & "_tmp" & "[[:digit:]]*"
  var ret = staticExec("find " & tmpFiles & " -type f -mmin +60 2> /dev/null | xargs -r rm")
  if ret.len > 0:
    echo ret

var tmpFileId {.compileTime.}: int = 0

proc execCode*(code: string, rstr: string): string {.compileTime.} =
  inc(tmpFileId)
  let tmpExeFile = binDir / srcFileName & "_tmp" & $tmpFileId & rstr
  let tmpSrcFile = tmpExeFile & srcFileExt
  writeFile(tmpSrcFile, code)
  echo staticExec("nim c " & tmpSrcFile)
  if not fileExists(tmpExeFile):
    rmFile(tmpSrcFile)
    macros.error "nim c failed"
  result = staticExec(tmpExeFile)
  removeTmpFiles(binDir)
  rmFile(tmpExeFile)
  rmFile(tmpSrcFile)

template execCode*(code: string): string = execCode(code, randomStr())

template staticExecCode*(code: string): string =
  block:
    macro execCodeResult(): string =
      nnkStmtList.newTree(
        newLit(execCode(code))
      )
    execCodeResult()

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
  let srcPath = currentSourcePath().parentDir()
  let downloadClosureCompiler = staticExec fmt"""
if [ -x "$(command -v google-closure-compiler)" ]; then
  echo "download closure-compiler skip"
elif ls "{srcPath}"/closure-compiler-*.jar 1> /dev/null 2>&1; then
  echo "download closure-compiler skip"
else
  mvn dependency:get -Ddest="{srcPath}" -Dartifact=com.google.javascript:closure-compiler:LATEST
fi
"""
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
  echo staticExecCode("""
echo "hello"
""")
  echo staticExecCode("""
echo "hello!"
""")
  echo compileJsCode(binDir, """
echo "hello!"
""")
