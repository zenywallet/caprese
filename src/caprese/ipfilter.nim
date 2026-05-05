# Copyright (c) 2026 zenywallet

import std/strutils
import std/sequtils
import std/bitops
import std/algorithm
import std/posix
import std/macros
import std/locks
import arraylib
import bytes

type
  RangeIp = tuple[ipLow: uint32, ipHigh: uint32]
  AllowIp = tuple[ip: uint32, allow: bool]

  AllowIpTable = object
    table: Array[AllowIp]
    allowAllFlag: bool

var allowRangeIp: Array[RangeIp]
var denyRangeIp: Array[RangeIp]
var allowRangeStart: int
var denyRangeStart: int

var allowIpTable1, allowIpTable2: AllowIpTable
var tmpAllowIpTable = addr allowIpTable1
var allowIpTable = addr allowIpTable2
var bulkIp: Array[uint32]
var ipFilterCommitLock: Lock
initLock(ipFilterCommitLock)
#deinitLock(ipFilterCommitLock)

proc resetIpTable*() =
  acquire(ipFilterCommitLock)
  allowRangeIp.clear()
  denyRangeIp.clear()
  allowRangeStart = 0
  denyRangeStart = 0
  tmpAllowIpTable[].table.setLen(0)
  bulkIp.setLen(0)
  tmpAllowIpTable[].allowAllFlag = true
  release(ipFilterCommitLock)

proc allowAll*() =
  tmpAllowIpTable[].allowAllFlag = true

proc denyAll*() =
  tmpAllowIpTable[].allowAllFlag = false

proc parseIp(ip: string): tuple[ipLow, ipHigh: uint32] =
  let parts = ip.split('/')
  if parts.len == 2:
    let parts1 = parts[0].split('.')
    var targetIp = when system.cpuEndian == bigEndian:
      parseUint(parts1[3]).uint32 shl 24 or
      parseUint(parts1[2]).uint32 shl 16 or
      parseUint(parts1[1]).uint32 shl 8 or
      parseUint(parts1[0]).uint32
    else:
      parseUint(parts1[0]).uint32 shl 24 or
      parseUint(parts1[1]).uint32 shl 16 or
      parseUint(parts1[2]).uint32 shl 8 or
      parseUint(parts1[3]).uint32
    let bit = try:
      parseUint(parts[1]).int
    except:
      let parts2 = parts[1].split('.')
      var n: uint32 = parseUint(parts2[0]).uint32 shl 24 or
                      parseUint(parts2[1]).uint32 shl 16 or
                      parseUint(parts2[2]).uint32 shl 8 or
                      parseUint(parts2[3]).uint32
      if n == 0: 0 else: 32 - countTrailingZeroBits(n)
    var mask0: uint32 = 0xFFFFFFFF'u32 shl (32 - bit)
    var mask: uint32 = when system.cpuEndian == bigEndian:
      (mask0 and 0xff000000'u32) shr 24 or
      (mask0 and 0x00ff0000'u32) shr 8 or
      (mask0 and 0x0000ff00'u32) shl 8 or
      (mask0 and 0x000000ff'u32) shl 24
    else:
      mask0
    var ipLow = targetIp and mask
    var ipHigh = targetIp or (0xffffffff'u32 xor mask)
    return (ipLow, ipHigh)

  elif parts.len == 1:
    var parts1 = parts[0].split('.')
    var targetIp = when system.cpuEndian == bigEndian:
      parseUint(parts1[3]).uint32 shl 24 or
      parseUint(parts1[2]).uint32 shl 16 or
      parseUint(parts1[1]).uint32 shl 8 or
      parseUint(parts1[0]).uint32
    else:
      parseUint(parts1[0]).uint32 shl 24 or
      parseUint(parts1[1]).uint32 shl 16 or
      parseUint(parts1[2]).uint32 shl 8 or
      parseUint(parts1[3]).uint32
    return (targetIp, targetIp)

proc allowIp*(ip: string) =
  var rangeIp = parseIp(ip)
  allowRangeIp.add(rangeIp)
  inc(rangeIp.ipHigh)
  bulkIp.add(rangeIp.ipLow)
  bulkIp.add(rangeIp.ipHigh)

proc denyIp*(ip: string) =
  var rangeIp = parseIp(ip)
  denyRangeIp.add(rangeIp)
  inc(rangeIp.ipHigh)
  bulkIp.add(rangeIp.ipLow)
  bulkIp.add(rangeIp.ipHigh)

proc checkIpRange(ip: uint32): bool =
  if tmpAllowIpTable[].allowAllFlag:
    for i in allowRangeStart..<allowRangeIp.len:
      let rangeIp = allowRangeIp[i]
      if ip >= rangeIp.ipLow and ip <= rangeIp.ipHigh:
        allowRangeStart = i
        return true
    for i in denyRangeStart..<denyRangeIp.len:
      let rangeIp = denyRangeIp[i]
      if ip >= rangeIp.ipLow and ip <= rangeIp.ipHigh:
        denyRangeStart = i
        return false
    return true
  else:
    for i in denyRangeStart..<denyRangeIp.len:
      let rangeIp = denyRangeIp[i]
      if ip >= rangeIp.ipLow and ip <= rangeIp.ipHigh:
        denyRangeStart = i
        return false
    for i in allowRangeStart..<allowRangeIp.len:
      let rangeIp = allowRangeIp[i]
      if ip >= rangeIp.ipLow and ip <= rangeIp.ipHigh:
        allowRangeStart = i
        return true
    return false

proc commitIpFilter*() =
  acquire(ipFilterCommitLock)
  bulkIp.add(0'u32)
  bulkIp.toOpenArray().sort(cmp)
  var bulkIp: seq[uint32] = deduplicate(bulkIp.toOpenArray(), isSorted = true)
  allowRangeIp.toOpenArray().sort(proc(x, y: RangeIp): int = cmp(x.ipLow, y.ipLow))
  denyRangeIp.toOpenArray().sort(proc(x, y: RangeIp): int = cmp(x.ipLow, y.ipLow))
  let ip = bulkIp[0]
  let allow = checkIpRange(ip)
  tmpAllowIpTable[].table.add (ip, allow)
  var curAllow = allow
  for i in 1..bulkIp.high:
    let ip = bulkIp[i]
    let allow = checkIpRange(ip)
    if allow != curAllow:
      curAllow = allow
      tmpAllowIpTable[].table.add (ip, allow)
  var tmp = allowIpTable
  allowIpTable = tmpAllowIpTable
  tmpAllowIpTable = tmp
  discard usleep(100) # > checkIp time
  release(ipFilterCommitLock)

proc checkIp*(ip: uint32): bool = # ip: host byte order
  var a = allowIpTable
  var r = a[].table.high
  if r < 0:
    return a[].allowAllFlag
  var l = 0
  while l <= r:
    let m = (l + r) shr 1
    if a[].table[m].ip < ip:
      l = m + 1
    else:
      r = m - 1
  if l <= a[].table.high and a[].table[l].ip == ip:
    a[].table[l].allow
  else:
    a[].table[r].allow

proc checkIp*(ip: string): bool = checkIp(posix.ntohl(inet_addr(ip.cstring)))

proc `$`*(rangeIp: AllowIp): string = $rangeIp.ip.toBytesBE & "-" & $rangeIp.allow

var ipFilterEnable* {.compileTime.}: bool = false

macro ipFilter*(rules: untyped): untyped =
  ipFilterEnable = true
  quote do:
    block:
      template default(body: untyped) = body
      template pass() = allowAll()
      template drop() = denyAll()
      template pass(ip: string) = allowIp(ip)
      template drop(ip: string) = denyIp(ip)
      resetIpTable()
      `rules`
      commitIpFilter()


when isMainModule:
  ipFilter:
    default pass
    drop "192.168.0.0/24"
    drop "100.0.0.0/16"
    drop "100.0.1.0/255.255.255.0"
    drop "10.0.0.1"
    pass "100.0.2.0/24"

  echo $allowIpTable[].table

  proc checkIpTest(ip: string) =
    echo ip, " - ", checkIp(ip)

  checkIpTest("192.168.0.0")
  checkIpTest("192.168.0.1")
  checkIpTest("192.167.255.255")
  checkIpTest("192.168.0.255")
  checkIpTest("192.168.1.0")
  checkIpTest("10.0.0.0")
  checkIpTest("10.0.0.1")
  checkIpTest("10.0.0.2")
  checkIpTest("100.0.0.1")
  checkIpTest("100.0.1.1")
  checkIpTest("100.0.2.1")
  checkIpTest("100.0.3.1")
