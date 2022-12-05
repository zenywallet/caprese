# Copyright (c) 2022 zenywallet

import os
import macros

const srcFile = currentSourcePath()
const (srcFileDir, srcFieName, srcFileExt) = splitFile(srcFile)
const execHelperExe = srcFileDir / "exec_helper"
const execHelperSrc = execHelperExe & srcFileExt

macro buildExecHelper() =
  echo staticExec("nim c " & execHelperSrc)
buildExecHelper()

proc randomStr*(): string {.compileTime.} = staticExec(execHelperExe & " randomstr")

proc rmFile*(filename: string) {.compileTime.} =
  echo staticExec(execHelperExe & " rmfile " & filename)

var tmpFileId {.compileTime.}: int = 0

proc execCode*(code: string, rstr: string): string {.compileTime.} =
  inc(tmpFileId)
  let tmpExeFile = srcFileDir / srcFieName & "_tmp" & $tmpFileId & rstr
  let tmpSrcFile = tmpExeFile & srcFileExt
  writeFile(tmpSrcFile, code)
  echo staticExec("nim c " & tmpSrcFile)
  result = staticExec(tmpExeFile)
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


when isMainModule:
  echo staticExecCode("""
echo "hello"
""")
  echo staticExecCode("""
echo "hello!"
""")
