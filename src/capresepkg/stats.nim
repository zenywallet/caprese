# Copyright (c) 2021 zenywallet

import times, sequtils, tables

type
  CheckReqs* = ref object
    reqs: seq[tuple[target: uint32, time: float]]
    table: CountTable[uint32]
    sec: float

proc newCheckReqs*(sec: float): CheckReqs =
  result = new CheckReqs
  result.table = initCountTable[uint32]()
  result.sec = sec

proc purgeReqs*(cr: CheckReqs, sec: float = -1): float {.discardable.} =
  var time = epochTime()
  var prevTime = time - (if sec >= 0: sec else: cr.sec)
  var pos = cr.reqs.len
  for i in 0..<cr.reqs.len:
    if cr.reqs[i].time > prevTime:
      pos = i
      break
  if pos > 0:
    for i in 0..<pos:
      cr.table.inc(cr.reqs[i].target, -1)
    cr.reqs.delete(0..pos - 1)
  result = time

proc checkReq*(cr: CheckReqs, target: uint32, sec: float = -1): int =
  var time = cr.purgeReqs(sec)
  cr.reqs.add((target, time))
  cr.table.inc(target)
  result = cr.table[target]


when isMainModule:
  import os, algorithm

  var cr = newCheckReqs(10)

  for i in 0..<10:
    for j in 0..<10:
      echo j, ": ", cr.checkReq(j.uint32)
      sleep 100
      var tmpTable = cr.table
      tmpTable.sort(SortOrder.Descending)
      echo tmpTable

  while cr.table.len > 0:
    cr.purgeReqs()
    var tmpTable = cr.table
    tmpTable.sort(SortOrder.Descending)
    echo tmpTable
    sleep 100
