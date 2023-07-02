# Copyright (c) 2022 zenywallet

import os
import macros
import strformat
import strutils

const srcFile = currentSourcePath()
const (srcFileDir, srcFileName, srcFileExt) = splitFile(srcFile)
const execHelperExe = srcFileDir / "exec_helper"
const execHelperSrc = execHelperExe & srcFileExt

macro buildExecHelper() =
  echo staticExec("nim c " & execHelperSrc)
buildExecHelper()

proc randomStr*(): string {.compileTime.} = staticExec(execHelperExe & " randomstr")

proc rmFile*(filename: string) {.compileTime.} =
  echo staticExec(execHelperExe & " rmfile " & filename)

proc basicExtern*(filename: string): string {.compileTime.} =
  staticExec(execHelperExe & " basicextern " & filename)

proc removeTmpFiles() {.compileTime.} =
  var tmpFiles = "\"" & srcFileDir / srcFileName & "_tmp" & "\"[[:digit:]]*"
  var ret = staticExec("rm " & tmpFiles)
  if ret.len > 0:
    echo ret

var tmpFileId {.compileTime.}: int = 0

proc execCode*(code: string, rstr: string): string {.compileTime.} =
  inc(tmpFileId)
  let tmpExeFile = srcFileDir / srcFileName & "_tmp" & $tmpFileId & rstr
  let tmpSrcFile = tmpExeFile & srcFileExt
  writeFile(tmpSrcFile, code)
  echo staticExec("nim c " & tmpSrcFile)
  result = staticExec(tmpExeFile)
  removeTmpFiles()
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
  result = readFile(tmpJsFile)
  result = removeThreadVarPatch(result)
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
  let closureCompiler = staticExec fmt"""
if [ -x "$(command -v google-closure-compiler)" ]; then
  closure_compiler="google-closure-compiler"
elif ls ../closure-compiler-*.jar 1> /dev/null 2>&1; then
  closure_compiler="java -jar $(ls ../closure-compiler-*.jar | sort -r | head -n1)"
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
  echo compileJsCode(srcFileDir, """
echo "hello!"
""")
