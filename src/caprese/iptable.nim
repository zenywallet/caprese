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
  IpRange[T] = tuple[ipLow: uint32, ipHigh: uint32, data: T]
  IpTable[T] = tuple[ip: uint32, data: T]
  IpTableObj[T] = object
    ipRange: Array[IpRange[T]]
    ipTable: ptr Array[IpTable[T]]
    ipTableTmp: ptr Array[IpTable[T]]
    ipTable1: Array[IpTable[T]]
    ipTable2: Array[IpTable[T]]
    bulkIp: Array[uint32]
    rangeStart: int
    default: T
    commitLock: Lock

proc newIpTable*[T](): IpTableObj[T] =
  result.ipTable = addr result.ipTable1
  result.ipTableTmp = addr result.ipTable2
  initLock(result.commitLock)

proc setDefaultData*[T](table: var IpTableObj[T]; default: T) =
  table.default = default

proc resetIpTable*[T](table: var IpTableObj[T]) =
  acquire(table.commitLock)
  table.ipRange.clear()
  table.ipTableTmp[].setLen(0)
  table.bulkIp.setLen(0)
  table.rangeStart = 0
  release(table.commitLock)

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

proc addIpData*[T](table: var IpTableObj[T]; ip: string; data: T) =
  var rangeIp = parseIp(ip)
  table.ipRange.add((rangeIp[0], rangeIp[1], data))
  inc(rangeIp.ipHigh)
  table.bulkIp.add(rangeIp.ipLow)
  table.bulkIp.add(rangeIp.ipHigh)

proc getIpRangeData[T](table: var IpTableObj[T]; ip: uint32): T =
  for i in table.rangeStart..<table.ipRange.len:
    let rangeIp = table.ipRange[i]
    if ip >= rangeIp.ipLow and ip <= rangeIp.ipHigh:
      table.rangeStart = i
      return rangeIp.data
  return table.default

proc commitIpData*[T](table: var IpTableObj[T]) =
  acquire(table.commitLock)
  table.bulkIp.add(0'u32)
  table.bulkIp.toOpenArray().sort(cmp)
  var bulkIp: seq[uint32] = deduplicate(table.bulkIp.toOpenArray(), isSorted = true)
  table.ipRange.toOpenArray().sort(proc(x, y: IpRange[T]): int = cmp(x.ipLow, y.ipLow))
  let ip = bulkIp[0]
  let data = table.getIpRangeData(ip)
  table.ipTableTmp[].add (ip, data)
  var curData = data
  for i in 1..bulkIp.high:
    let ip = bulkIp[i]
    let data = table.getIpRangeData(ip)
    if cmpMem(addr data, addr curData, sizeof(T)) != 0:
      curData = data
      table.ipTableTmp[].add (ip, data)
  if table.ipTable == addr table.ipTable1:
    table.ipTable = addr table.ipTable2
    table.ipTableTmp = addr table.ipTable1
  else:
    table.ipTable = addr table.ipTable1
    table.ipTableTmp = addr table.ipTable2
  discard usleep(100) # > getIpData time
  release(table.commitLock)

proc getIpData*[T](table: var IpTableObj[T]; ip: uint32): T = # ip: host byte order
  var a = table.ipTable
  var r = a[].high
  if r < 0:
    return table.default
  var l = 0
  while l <= r:
    let m = (l + r) shr 1
    if a[][m].ip < ip:
      l = m + 1
    else:
      r = m - 1
  if l <= a[].high and a[][l].ip == ip:
    a[][l].data
  else:
    a[][r].data

proc getIpData*[T](table: var IpTableObj[T]; ip: string): T {.inline.} =
  table.getIpData(posix.ntohl(inet_addr(ip.cstring)))

proc toIpString*(ip: uint32): string =
  $(ip shr 24 and 0xff) & "." &
  $(ip shr 16 and 0xff) & "." &
  $(ip shr 8 and 0xff) & "." &
  $(ip and 0xff)


when isMainModule:
  import contents

  type
    IpInfo = object
      countryCode: String
      connLimit: int
      rateLimit: int

  var ipInfoTable = newIpTable[IpInfo]()
  ipInfoTable.setDefaultData(IpInfo(countryCode: "", connLimit: 10, rateLimit: 5))
  ipInfoTable.resetIpTable()
  ipInfoTable.addIpData("127.0.0.0/8", IpInfo(countryCode: "JP", connLimit: 100, rateLimit: 60))
  ipInfoTable.commitIpData()

  echo ipInfoTable.getIpData("127.0.0.1")
