# Copyright (c) 2020 zenywallet

import sequtils, strutils, endians, algorithm
import opcodes

type
  VarInt* = distinct int

  VarStr* = distinct string

  Pad* = distinct int

  FixedStr* = ref object
    data*: string
    size*: int

  Hash* = distinct seq[byte]

  Hash160* = distinct seq[byte]

  PushData* = distinct seq[byte]

  Hex* = distinct string


proc toBytes*(x: SomeOrdinal | SomeFloat): seq[byte] =
  when sizeof(x) == 1:
    @[byte x]
  else:
    result = newSeq[byte](sizeof(x))
    when sizeof(x) == 2:
      littleEndian16(addr result[0], unsafeAddr x)
    elif sizeof(x) == 4:
      littleEndian32(addr result[0], unsafeAddr x)
    elif sizeof(x) == 8:
      littleEndian64(addr result[0], unsafeAddr x)
    else:
      raiseAssert("toBytes: unsupported type")

proc toBytesBE*(x: SomeOrdinal | SomeFloat): seq[byte] =
  when sizeof(x) == 1:
    @[byte x]
  else:
    result = newSeq[byte](sizeof(x))
    when sizeof(x) == 2:
      bigEndian16(addr result[0], unsafeAddr x)
    elif sizeof(x) == 4:
      bigEndian32(addr result[0], unsafeAddr x)
    elif sizeof(x) == 8:
      bigEndian64(addr result[0], unsafeAddr x)
    else:
      raiseAssert("toBytes: unsupported type")

proc toBE*[T](x: T): T =
  when sizeof(x) == 1:
    x
  elif sizeof(x) == 2:
    bigEndian16(addr result, unsafeAddr x)
  elif sizeof(x) == 4:
    bigEndian32(addr result, unsafeAddr x)
  elif sizeof(x) == 8:
    bigEndian64(addr result, unsafeAddr x)
  else:
    raiseAssert("toBE: unsupported type")

proc varInt*[T](val: T): seq[byte] =
  if val < 0xfd:
    @[byte val]
  elif val <= 0xffff:
    concat(@[byte 0xfd], (uint16(val)).toBytes)
  elif val <= 0xffffffff:
    concat(@[byte 0xfe], (uint32(val)).toBytes)
  else:
    concat(@[byte 0xff], (uint64(val)).toBytes)

proc varStr*(s: string): seq[byte] {.inline.} = concat(varInt(s.len), cast[seq[byte]](s))

proc pushData*(data: seq[byte]): seq[byte] =
  if data.len <= 0:
    raiseAssert("pushData: empty")
  elif data.len < OP_PUSHDATA1.ord:
    result = concat(@[byte data.len], data)
  elif data.len <= 0xff:
    result = concat(@[byte OP_PUSHDATA1], (data.len).uint8.toBytes, data)
  elif data.len <= 0xffff:
    result = concat(@[byte OP_PUSHDATA2], (data.len).uint16.toBytes, data)
  elif data.len <= 0xffffffff:
    result = concat(@[byte OP_PUSHDATA4], (data.len).uint32.toBytes, data)
  else:
    raiseAssert("pushData: overflow")

proc pushData*(data: openarray[byte]): seq[byte] {.inline.} = pushData(data.toSeq)

proc pad*(len: int): seq[byte] {.inline.} = newSeq[byte](len)

proc pad*(len: int, val: byte): seq[byte] {.inline.} =
  result = newSeqUninitialized[byte](len)
  result.fill(val)

proc newFixedStr*(data: string, size: int): FixedStr {.inline.} = FixedStr(data: data, size: size)

proc fixedStr*(str: string, size: int): seq[byte] {.inline.} =
  if size < str.len:
    concat(cast[seq[byte]](str)[0..<size])
  else:
    concat(cast[seq[byte]](str), pad(size - str.len))

proc toBytes*(x: seq[byte]): seq[byte] {.inline.} = x
proc toBytes*(x: openarray[byte]): seq[byte] {.inline.} = x.toSeq
proc toBytes*(val: VarInt): seq[byte] {.inline.} = varInt(cast[int](val))
proc toBytes*(str: VarStr): seq[byte] {.inline.} = varStr(cast[string](str))
proc toBytes*(len: Pad): seq[byte] {.inline.} = pad(cast[int](len))
proc toBytes*(fstr: FixedStr): seq[byte] {.inline.} = fixedStr(fstr.data, fstr.size)
proc toBytes*(hash: Hash): seq[byte] {.inline.} = cast[seq[byte]](hash)
proc toBytes*(hash: Hash160): seq[byte] {.inline.} = cast[seq[byte]](hash)
proc toBytes*(p: PushData): seq[byte] {.inline.} = pushData(cast[seq[byte]](p))
proc toBytes*(x: string): seq[byte] {.inline.} = cast[seq[byte]](x)

proc toBytes*(obj: tuple | object): seq[byte] =
  var s: seq[seq[byte]]
  for val in obj.fields:
    var b = val.toBytes
    s.add(b)
  concat(s)

proc toBytes*[T](obj: openarray[T]): seq[byte] =
  var s: seq[seq[byte]]
  for val in obj:
    var b = val.toBytes
    s.add(b)
  concat(s)

proc toBytes*(obj: ref tuple | ref object | ptr tuple | ptr object): seq[byte] =
  var s: seq[seq[byte]]
  for val in obj[].fields:
    var b = val.toBytes
    s.add(b)
  concat(s)

proc toBytes*(buf: ptr UncheckedArray[byte], size: SomeInteger): seq[byte] =
  result = newSeqOfCap[byte](size)
  for i in 0..<size:
    result.add(buf[i])

proc Bytes*(args: varargs[seq[byte], toBytes]): seq[byte] = concat(args)

proc toBytesBE*(x: seq[byte]): seq[byte] {.inline.} = x
proc toBytesBE*(x: openarray[byte]): seq[byte] {.inline.} = x.toSeq
proc toBytesBE*(hash: Hash): seq[byte] {.inline.} = cast[seq[byte]](hash)
proc toBytesBE*(hash: Hash160): seq[byte] {.inline.} = cast[seq[byte]](hash)
proc toBytesBE*(x: string): seq[byte] {.inline.} = cast[seq[byte]](x)

proc toBytesBE*(obj: tuple | object): seq[byte] =
  var s: seq[seq[byte]]
  for val in obj.fields:
    var b = val.toBytesBE
    s.add(b)
  concat(s)

proc toBytesBE*(obj: ref tuple | ref object | ptr tuple | ptr object): seq[byte] =
  var s: seq[seq[byte]]
  for val in obj[].fields:
    var b = val.toBytesBE
    s.add(b)
  concat(s)

proc BytesBE*(x: SomeOrdinal | SomeFloat): seq[byte] {.inline.} = x.toBytesBE
proc BytesBE*(args: varargs[seq[byte], toBytesBE]): seq[byte] = concat(args)

proc toBytesFromHex*(s: string): seq[byte] =
  if s.len mod 2 == 0:
    result = newSeqOfCap[byte](s.len div 2)
    for i in countup(0, s.len - 2, 2):
      result.add(strutils.fromHex[byte](s[i..i+1]))
  else:
    result = @[]

proc toBytes*(x: Hex): seq[byte] {.inline.} = x.string.toBytesFromHex()

proc toReverse*(x: seq[byte]): seq[byte] =
  var b = x
  algorithm.reverse(b)
  b

proc to*(x: var byte, T: typedesc): T {.inline.} = cast[ptr T](addr x)[]
proc toUint8*(x: var byte): uint8 {.inline.} = x.uint8
proc toUint16*(x: var byte): uint16 {.inline.} = cast[ptr uint16](addr x)[]
proc toUint32*(x: var byte): uint32 {.inline.} = cast[ptr uint32](addr x)[]
proc toUint64*(x: var byte): uint64 {.inline.} = cast[ptr uint64](addr x)[]

proc to*(x: openarray[byte], T: typedesc): T {.inline.} = cast[ptr T](unsafeAddr x[0])[]
proc toUint8*(x: openarray[byte]): uint8 {.inline.} = x[0].uint8
proc toUint16*(x: openarray[byte]): uint16 {.inline.} = cast[ptr uint16](unsafeAddr x[0])[]
proc toUint32*(x: openarray[byte]): uint32 {.inline.} = cast[ptr uint32](unsafeAddr x[0])[]
proc toUint64*(x: openarray[byte]): uint64 {.inline.} = cast[ptr uint64](unsafeAddr x[0])[]

proc toBE*(x: var byte, T: typedesc): T {.inline.} = to(x, T)
proc toUint8BE*(x: var byte): uint8 {.inline.} = x.uint8
proc toUint16BE*(x: var byte): uint16 {.inline.} = x.toUint16.toBE
proc toUint32BE*(x: var byte): uint32 {.inline.} = x.toUint32.toBE
proc toUint64BE*(x: var byte): uint64 {.inline.} = x.toUint64.toBE

proc toBE*(x: openarray[byte], T: typedesc): T {.inline.} = cast[ptr T](unsafeAddr x[0])[]
proc toUint8BE*(x: openarray[byte]): uint8 {.inline.} = x[0].uint8
proc toUint16BE*(x: openarray[byte]): uint16 {.inline.} = x.toUint16.toBE
proc toUint32BE*(x: openarray[byte]): uint32 {.inline.} = x.toUint32.toBE
proc toUint64BE*(x: openarray[byte]): uint64 {.inline.} = x.toUint64.toBE

proc toHash*(x: var byte): Hash {.inline.} = Hash((cast[ptr array[32, byte]](addr x)[]).toSeq)
proc toHash*(x: seq[byte]): Hash {.inline.} = Hash(x)
proc toHash*(x: openarray[byte]): Hash {.inline.} = Hash(x.toSeq)
proc toHash*(x: Hex): Hash {.inline} = x.toBytes.toReverse.Hash

proc toHash160*(x: var byte): Hash160 {.inline.} = Hash160((cast[ptr array[20, byte]](addr x)[]).toSeq)
proc toHash160*(x: seq[byte]): Hash160 {.inline.} = Hash160(x)
proc toHash160*(x: openarray[byte]): Hash160 {.inline.} = Hash160(x.toSeq)

when not defined(CSTRING_SAFE):
  proc toString*(s: seq[byte]): string = cast[string](s)

proc toString*(s: openarray[byte]): string =
  result = newStringOfCap(len(s))
  for c in s:
    result.add(cast[char](c))

proc toString*(buf: ptr UncheckedArray[byte], size: SomeInteger): string =
  result = newStringOfCap(size)
  for i in 0..<size:
    result.add(cast[char](buf[i]))

const TOHEX_COMPACT = false
when TOHEX_COMPACT:
  const hexChars = "0123456789abcdef"

  proc toHex*(a: openarray[byte]): string =
    result = newStringOfCap(a.len * 2)
    for i in 0..a.high:
      result.add(hexChars[(a[i] and 0xf0'u8) shr 4])
      result.add(hexChars[a[i] and 0x0f'u8])
else:
  const hexStr = ["00", "01", "02", "03", "04", "05", "06", "07",
                  "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
                  "10", "11", "12", "13", "14", "15", "16", "17",
                  "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
                  "20", "21", "22", "23", "24", "25", "26", "27",
                  "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
                  "30", "31", "32", "33", "34", "35", "36", "37",
                  "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
                  "40", "41", "42", "43", "44", "45", "46", "47",
                  "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
                  "50", "51", "52", "53", "54", "55", "56", "57",
                  "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
                  "60", "61", "62", "63", "64", "65", "66", "67",
                  "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
                  "70", "71", "72", "73", "74", "75", "76", "77",
                  "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
                  "80", "81", "82", "83", "84", "85", "86", "87",
                  "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
                  "90", "91", "92", "93", "94", "95", "96", "97",
                  "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
                  "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
                  "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
                  "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
                  "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
                  "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
                  "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
                  "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
                  "d8", "d9", "da", "db", "dc", "dd", "de", "df",
                  "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
                  "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
                  "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
                  "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"]

  proc toHex*(a: openarray[byte]): string =
    result = newStringOfCap(a.len * 2)
    for i in 0..a.high:
      result.add(hexStr[a[i]])

proc `$`*(data: seq[byte]): string =
  if data.len > 0:
    result = bytes.toHex(data)
  else:
    result = ""

proc `$`*(val: VarInt): string = "VarInt(" & $cast[int](val) & ")"

proc `$`*(str: VarStr): string = "VarStr(\"" & $cast[string](str) & "\")"

proc `$`*(len: Pad): string = "Pad(" & $cast[int](len) & ")"

proc `$`*(fstr: FixedStr): string = "FixedStr(\"" & fstr.data & "\", " & $fstr.size & ")"

proc `$`*(data: Hash): string =
  var b = cast[seq[byte]](data)
  algorithm.reverse(b)
  bytes.toHex(b)

proc `$`*(data: Hash160): string = data.toBytes.toHex

proc `$`*(p: PushData): string =
  var op: string
  var b = cast[seq[byte]](p)
  var len = b.len
  if len < OP_PUSHDATA1.ord:
    op = "PushData"
  elif len <= 0xff:
    op = "PushData1"
  elif len <= 0xffff:
    op = "PushData2"
  elif len <= 0xffffffff:
    op = "PushData4"
  else:
    raiseAssert("pushdata overflow")
  result = op & "(" & $len & ", " & $b & ")"

proc `$`*(o: ref tuple | ref object | ptr tuple | ptr object): string = $o[]

proc `==`*(x, y: Hash | Hash160): bool = x.toBytes == y.toBytes
