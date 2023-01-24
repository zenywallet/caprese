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
  var internalEssentialHeaders = @[("InternalEssentialHeaderConnection", "Connection")]
  var internalEssentialConst = nnkStmtList.newTree()

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

  for a in body:
    for i, b in internalEssentialHeaders:
      if $a[1][0] == b[1]:
        internalEssentialConst.add(
          nnkConstSection.newTree(
            nnkConstDef.newTree(
              newIdentNode(b[0]),
              newEmptyNode(),
              newIdentNode($a[0])
            )
          ))
        internalEssentialHeaders.delete(i)
        break

  for b in internalEssentialHeaders:
    enumParams.add(newIdentNode(b[0]))
    targetParams.add(newLit(b[1] & ": "))
    headers.add(nnkTupleConstr.newTree(
      nnkExprColonExpr.newTree(
        newIdentNode("id"),
        newIdentNode(b[0])
      ),
      nnkExprColonExpr.newTree(
        newIdentNode("val"),
        newLit(b[1])
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
    internalEssentialConst,
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
