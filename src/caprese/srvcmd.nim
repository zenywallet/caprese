# Copyright (c) 2025 zenywallet

import std/macros
import utils

var srvCmdList {.compileTime.}: seq[string]
var srvCmdBody {.compileTime.} = newStmtList()
var srvCmdSkip {.compileTime.} = true

template srvcmd_tmpl(name, body: untyped) =
  var nameStr = name.strVal
  block FindCmd:
    for c in srvCmdList:
      if c == nameStr:
        break FindCmd
    srvCmdList.add(nameStr)
  if body.kind == nnkMacroDef:
    body[^1].insert(0, nnkCall.newTree(ident("setSrvCmdUsage"), name))
  elif body.kind == nnkTemplateDef:
    body[^1].insert(0, nnkCall.newTree(ident("setSrvCmdUsageMacro"), name))
  else:
    error("srvcmd workds with nnkMacroDef or nnkTemplateDef, not " & $body.kind)
  srvCmdBody.add(body)
  discard

template getProcNameNode(body: untyped): untyped =
  if body[0].kind == nnkPostfix: body[0][1] else: body[0]

macro srvcmd*(body: untyped) = srvcmd_tmpl(getProcNameNode(body), body)

macro srvcmd*(name, body: untyped) = srvcmd_tmpl(name, body)

macro srvcmd_nomap*(body: untyped) =
  srvCmdBody.add(body)
  discard

macro addSrvCmd*(name: untyped) =
  srvCmdList.add(name.strVal)

macro srvCmdBodyMacro(): untyped = srvCmdBody

macro genCmdListType(objName: untyped, varType: typedesc): untyped =
  result = nnkTypeSection.newTree(
    nnkTypeDef.newTree(
      objName,
      newEmptyNode(),
      nnkObjectTy.newTree(
        newEmptyNode(),
        newEmptyNode(),
        nnkRecList.newTree()
      )
    )
  )
  for cmd in srvCmdList:
    result[0][2][2].add nnkIdentDefs.newTree(
      newIdentNode(cmd),
      varType,
      newEmptyNode()
    )

template commitSrvCmd*() =
  genCmdListType(SrvCmdFlag, bool)
  genCmdListType(SrvCmdCount, int)
  var srvCmdFlagList {.compileTime.}: seq[SrvCmdFlag]
  var srvCmdCountList {.compileTime.}: seq[SrvCmdCount]

  proc newSrvCmdUsage*() {.compileTime.} =
    srvCmdFlagList.add(SrvCmdFlag())
    srvCmdCountList.add(SrvCmdCount())

  macro getField(obj: object, field: static string): untyped =
    newDotExpr(obj, ident(field))

  macro staticIdentStr(s: typed): untyped = newLit($s)

  template setSrvCmdUsage*(cmd: typed, flag: bool = true) =
    if not srvCmdSkip:
      srvCmdFlagList[0].getField(staticIdentStr(cmd)) = flag
      inc(srvCmdCountList[0].getField(staticIdentStr(cmd)))
      srvCmdFlagList[^1].getField(staticIdentStr(cmd)) = flag
      inc(srvCmdCountList[^1].getField(staticIdentStr(cmd)))

  template setSrvCmdUsageMacro*(cmd: typed, flag: bool = true) =
    doMacro:
      if not srvCmdSkip:
        srvCmdFlagList[0].getField(staticIdentStr(cmd)) = flag
        inc(srvCmdCountList[0].getField(staticIdentStr(cmd)))
        srvCmdFlagList[^1].getField(staticIdentStr(cmd)) = flag
        inc(srvCmdCountList[^1].getField(staticIdentStr(cmd)))

  doMacro:
    newSrvCmdUsage()

  template getSrvCmdFlag*(): SrvCmdFlag = srvCmdFlagList[^1]

  template getSrvCmdCount*(): SrvCmdCount = srvCmdCountList[^1]

  template getSrvCmdUsage*(): tuple[flag: SrvCmdFlag, count: SrvCmdCount] =
    (flag: srvCmdFlagList[^1], count: srvCmdCountList[^1])

  template getSrvCmdFlag*(id: int): SrvCmdFlag = srvCmdFlagList[id]

  template getSrvCmdCount*(id: int): SrvCmdCount = srvCmdCountList[id]

  template getSrvCmdUsage*(id: int): tuple[flag: SrvCmdFlag, count: SrvCmdCount] =
    (flag: srvCmdFlagList[id], count: srvCmdCountList[id])

  template getSrvCmdFlag*(id: int, cmd: typed): bool =
    srvCmdFlagList[id].getField(staticIdentStr(cmd))

  template getSrvCmdCount*(id: int, cmd: typed): int =
    srvCmdCountList[id].getField(staticIdentStr(cmd))

  template getSrvCmdUsage*(id: int, cmd: typed): tuple[flag: bool, count: int] =
    (flag: srvCmdFlagList[id].getField(staticIdentStr(cmd)),
    count: srvCmdCountList[id].getField(staticIdentStr(cmd)))

  srvCmdBodyMacro()

template withSrvCmd*(body: untyped) =
  doMacro:
    srvCmdSkip = false
  body
  doMacro:
    srvCmdSkip = true
