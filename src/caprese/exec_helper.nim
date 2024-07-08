# Copyright (c) 2022 zenywallet

import os
import random
import nre
import tables
import strutils

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

if paramCount() == 1:
  if paramStr(1) == "randomstr":
    var r = initRand()
    var res = newString(13)
    for i in 0..<res.len:
      res[i] = r.sample(letters)
    echo res

elif paramCount() == 2:
  if paramStr(1) == "rmfile":
    removeFile(paramStr(2))
    echo "rm ", paramStr(2)

  if paramStr(1) == "basicextern":
    var list = initOrderedTable[string, string]()
    var resList = initOrderedTable[string, string]()

    let targetJs = paramStr(2)
    let d = readFile(targetJs)

    for s in d.findIter(re""": "[a-zA-Z_][\w]*""""):
      var t = s.match.strip(chars = {' ', ':', '"'})
      list[t] = t

    for s in d.findIter(re"[a-zA-Z_][\w]*: "):
      var t = s.match.strip(chars = {' ', ':'})
      list[t] = t
      #if list.hasKey(t):
      #  resList[t] = t

    for s in d.findIter(re"\.[a-zA-Z_][\w]*"):
      var t = s.match.strip(chars = {'.'})
      if list.hasKey(t):
        resList[t] = t

    for s in d.findIter(re"\[""[a-zA-Z_][\w]*""\]"):
      var t = s.match.strip(chars = {'[', ']', '"'})
      if list.hasKey(t):
        resList[t] = t

    resList.sort(system.cmp)

    var res: string
    res.add("\nvar basic_externs = {\n")
    var last = resList.len
    var i = 0
    for s in resList.keys:
      inc(i)
      if i == last:
        res.add("  " & s & ": 0\n")
      else:
        res.add("  " & s & ": 0,\n")
    res.add("};\n")

    echo res
