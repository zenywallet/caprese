# Copyright (c) 2022 zenywallet

import macros

type
  ClientId* = int

  SendResult* {.pure.} = enum
    Error = -1
    None = 0
    Success = 1
    Pending = 2
    Invalid = 3


macro HttpTargetHeader(idEnumName, valListName, targetHeaders, body: untyped): untyped =
  var enumParams = nnkEnumTy.newTree(newEmptyNode())
  var targetParams = nnkBracket.newTree()
  var headers = nnkBracket.newTree()
  for a in body:
    enumParams.add(a[0])
    var paramLit = newLit($a[1][0] & ": ")
    targetParams.add(paramLit)
    headers.add(nnkTupleConstr.newTree(
      nnkExprColonExpr.newTree(
        newIdentNode("id"),
        a[0]
      ),
      nnkExprColonExpr.newTree(
        newIdentNode("val"),
        paramLit
      )
    ))

  nnkStmtList.newTree(
    nnkTypeSection.newTree(
      nnkTypeDef.newTree(
        idEnumName,
        newEmptyNode(),
        enumParams
      )
    ),
    nnkConstSection.newTree(
      nnkConstDef.newTree(
        valListName,
        newEmptyNode(),
        targetParams
      )
    ),
    nnkVarSection.newTree(
      nnkIdentDefs.newTree(
        targetHeaders,
        newEmptyNode(),
        nnkPrefix.newTree(
          newIdentNode("@^"),
          headers
        )
      )
    )
  )

macro HttpTargetHeader*(body: untyped): untyped =
  quote do:
    HttpTargetHeader(HeaderParams, TargetHeaderParams, TargetHeaders, `body`)
