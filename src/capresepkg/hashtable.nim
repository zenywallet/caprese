# Copyright (c) 2021 zenywallet

import std/memfiles

type
  HashTableDataObj*[Key, Val] {.packed.} = object
    key*: Key
    val*: Val

  HashTableData*[Key, Val] = ptr HashTableDataObj[Key, Val]

  HashTableBase*[Key, Val] = object of RootObj
    bitmap*: ptr UncheckedArray[byte]
    bitmapSize*: int

    table*: ptr UncheckedArray[HashTableDataObj[Key, Val]]
    tableSize*: int

    tableBuf*: ptr UncheckedArray[byte]
    tableBufSize*: int

    dataSize*: int
    dataLen*: int
    dataCount*: int

  HashTableMem*[Key, Val] = object of HashTableBase[Key, Val]

  HashTableMmap*[Key, Val] = object of HashTableBase[Key, Val]
    mmap*: MemFile

  HashTable*[Key, Val] = HashTableMem[Key, Val] | HashTableMmap[Key, Val]

  HashTableError* = object of CatchableError

template loadHashTableModules*() {.dirty.} =
  when not declared(bitops):
    import std/bitops
  when not declared(memfiles):
    import std/memfiles

  when not declared(DISABLE_HASHTABLEDATA_DELETE):
    const DISABLE_HASHTABLEDATA_DELETE = defined(DISABLE_HASHTABLEDATA_DELETE)
  when not DISABLE_HASHTABLEDATA_DELETE:
    when not declared(empty):
      {.warning: "missing custom proc empty*(pair: HashTableData): bool".}
      proc empty*(pair: HashTableData): bool = false
    when not declared(setEmpty):
      {.warning: "missing custom proc setEmpty*(pair: HashTableData)".}
      proc setEmpty*(pair: HashTableData) = discard
    when not declared(empty) or not declared(setEmpty):
      {.hint: "to disable hashtable data deletion, define DISABLE_HASHTABLEDATA_DELETE".}

  proc setBitmap*(hashTable: var HashTable, pos: int) =
    let bitPos = pos div 8
    let bitOffset = pos.uint8 and 0x7'u8
    hashTable.bitmap[bitPos].setBit(bitOffset)

  proc getBitmap*(hashTable: var HashTable, pos: int): uint8 =
    let bitPos = pos div 8
    let bitOffset = pos.uint8 and 0x7'u8
    result = hashTable.bitmap[bitPos].testBit(bitOffset).uint8

  iterator getBitmap(hashTable: var HashTable, pos: int = 0): uint8 =
    var curPos = pos
    let startPos = curPos div 8
    var bitOffset = curPos.uint8 and 0x7'u8
    for i in startPos..<hashTable.bitmapSize:
      let hb = hashTable.bitmap[i]
      for j in bitOffset..<8:
        if curPos < hashTable.dataLen:
          yield hb.testBit(j).uint8
          inc(curPos)

  proc countBitmap*(hashTable: var HashTable): int =
    let uint64len = hashTable.bitmapSize div 8
    let u8start = hashTable.bitmapSize - (hashTable.bitmapSize.uint8 and 0x7'u8).int
    let bitmap64 = cast[ptr UncheckedArray[uint64]](addr hashTable.bitmap[0])
    for i in 0..<uint64len:
      result = result + countSetBits(bitmap64[i])
    for i in u8start..<hashTable.bitmapSize:
      result = result + countSetBits(hashTable.bitmap[i])

  proc countData(hashTable: var HashTable): int =
    for hash in 0..<hashTable.dataLen:
      let used = hashTable.getBitmap(hash)
      if used != 0:
        let hashData = addr hashTable.table[hash]
        when not DISABLE_HASHTABLEDATA_DELETE and declared(empty):
          if not hashData.empty:
            inc(result)
        else:
          inc(result)

  proc newHashTable*[Key, Val](dataLen: int): HashTableMem[Key, Val] =
    result.dataSize = sizeof(HashTableDataObj[Key, Val])
    result.dataLen = dataLen
    result.bitmapSize = (result.dataLen + 7) div 8
    result.tableSize = result.dataSize * dataLen
    result.tableBufSize = result.bitmapSize + result.tableSize
    result.tableBuf = cast[ptr UncheckedArray[byte]](allocShared0(result.tableBufSize))
    result.bitmap = result.tableBuf
    result.table = cast[ptr UncheckedArray[HashTableDataObj[Key, Val]]](addr result.tableBuf[result.bitmapSize])

  proc openHashTable*[Key, Val](dataLen: int, mmapFile: string = ""): HashTableMmap[Key, Val] =
    result.dataSize = sizeof(HashTableDataObj[Key, Val])
    result.dataLen = dataLen
    result.bitmapSize = (result.dataLen + 7) div 8
    result.tableSize = result.dataSize * dataLen
    result.tableBufSize = result.bitmapSize + result.tableSize
    try:
      result.mmap = memfiles.open(mmapFile, mode = fmReadWrite, newFileSize = -1)
      result.tableBuf = cast[ptr UncheckedArray[byte]](result.mmap.mem)
      result.bitmap = result.tableBuf
      result.table = cast[ptr UncheckedArray[HashTableDataObj[Key, Val]]](addr result.tableBuf[result.bitmapSize])
      result.dataCount = result.countData()
    except:
      result.mmap = memfiles.open(mmapFile, mode = fmReadWrite, newFileSize = result.tableBufSize)
      result.tableBuf = cast[ptr UncheckedArray[byte]](result.mmap.mem)
      result.bitmap = result.tableBuf
      result.table = cast[ptr UncheckedArray[HashTableDataObj[Key, Val]]](addr result.tableBuf[result.bitmapSize])

  proc close*(hashTable: var HashTableMmap) =
    hashTable.mmap.close()

  proc flush*(hashTable: var HashTable) =
    when HashTable is HashTableMmap:
      hashTable.mmap.flush()
    else:
      discard

  proc delete*(hashTable: var HashTable) =
    when HashTable is HashTableMem:
      hashTable.tableBuf.deallocShared()
    elif HashTable is HashTableMmap:
      hashTable.mmap.close()

  proc clear*(hashTable: var HashTable) =
    zeroMem(hashTable.tableBuf, hashTable.tableBufSize)

  proc set*(pair: HashTableData, key: HashTableData.Key, val: HashTableData.Val) {.inline.} = pair.key = key; pair.val = val
  proc set*(pair: HashTableData, src: HashTableData) {.inline.} = pair[] = src[]
  proc setKey*(pair: HashTableData, key: HashTableData.Key) {.inline.} = pair.key = key
  proc setVal*(pair: HashTableData, val: HashTableData.Val) {.inline.} = pair.val = val

  proc set*[Key, Val](hashTable: var HashTable[Key, Val], key: Key, val: Val): HashTableData[Key, Val] {.discardable.} =
    when key is SomeOrdinal:
      var hash = (key.uint64 mod hashTable.dataLen.uint64).int
    else:
      var hash = (key.toUint64 mod hashTable.dataLen.uint64).int
    let startHash = hash
    while true:
      let used = hashTable.getBitmap(hash)
      let hashData = addr hashTable.table[hash]
      result = hashData
      if used == 0:
        hashTable.setBitmap(hash)
        hashData.set(key, val)
        inc(hashTable.dataCount)
        break
      else:
        when not DISABLE_HASHTABLEDATA_DELETE and declared(empty):
          if hashData.empty:
            hashData.set(key, val)
            inc(hashTable.dataCount)
            break
        if hashData.key == key:
          hashData.setVal(val)
          break
        else:
          inc(hash)
          if hash >= hashTable.dataLen:
            hash = 0
          if hash == startHash:
            raise newException(HashTableError, "hashtable data full")

  proc upsert*[Key, Val](hashTable: var HashTable[Key, Val], key: Key, val: Val,
                        cb: proc(hashData: HashTableData[Key, Val], val: Val)) =
    when key is SomeOrdinal:
      var hash = (key.uint64 mod hashTable.dataLen.uint64).int
    else:
      var hash = (key.toUint64 mod hashTable.dataLen.uint64).int
    let startHash = hash
    while true:
      let used = hashTable.getBitmap(hash)
      let hashData = addr hashTable.table[hash]
      if used == 0:
        hashTable.setBitmap(hash)
        hashData.set(key, val)
        inc(hashTable.dataCount)
        break
      else:
        when not DISABLE_HASHTABLEDATA_DELETE and declared(empty):
          if hashData.empty:
            hashData.set(key, val)
            inc(hashTable.dataCount)
            break
        if hashData.key == key:
          cb(hashData, val)
          break
        else:
          inc(hash)
          if hash >= hashTable.dataLen:
            hash = 0
          if hash == startHash:
            raise newException(HashTableError, "hashtable data full")

  proc get*[Key, Val](hashTable: var HashTable[Key, Val], key: Key): HashTableData[Key, Val] =
    when key is SomeOrdinal:
      var hash = (key.uint64 mod hashTable.dataLen.uint64).int
    else:
      var hash = (key.toUint64 mod hashTable.dataLen.uint64).int
    let startHash = hash
    while true:
      let used = hashTable.getBitmap(hash)
      if used == 1:
        let hashData = addr hashTable.table[hash]
        when not DISABLE_HASHTABLEDATA_DELETE and declared(empty):
          if not hashData.empty:
            let hashData = addr hashTable.table[hash]
            if hashData.key == key:
              return hashData
        else:
          if hashData.key == key:
            return hashData
        inc(hash)
        if hash >= hashTable.dataLen:
          hash = 0
        if hash == startHash:
          return nil
      else:
        return nil

  when not DISABLE_HASHTABLEDATA_DELETE and declared(setEmpty):
    proc del*(hashTable: var HashTable, pair: HashTableData) =
      pair.setEmpty()
      dec(hashTable.dataCount)

    proc del*(hashTable: var HashTable, key: HashTable.Key) =
      let pair = hashTable.get(key)
      if pair != nil:
        hashTable.del(pair)
  else:
    template del*(hashTable: var HashTable, key: HashTable.Key) = discard

  template copyBody() {.dirty.} =
    if srcHashTable.dataCount > dstHashTable.dataLen:
      raise newException(HashTableError, "dst is small src=" & $srcHashTable.dataCount & " dst=" & $dstHashTable.dataLen)

    for hash in 0..<srcHashTable.dataLen:
      let used = srcHashTable.getBitmap(hash)
      if used != 0:
        let hashData = addr srcHashTable.table[hash]
        when not DISABLE_HASHTABLEDATA_DELETE and declared(empty):
          if not hashData.empty:
            dstHashTable.set(hashData.key, hashData.val)
        else:
          dstHashTable.set(hashData.key, hashData.val)

  proc copy*(srcHashTable: var HashTable, dstHashTable: var HashTableMem) = copyBody()
  proc copy*(srcHashTable: var HashTable, dstHashTable: var HashTableMmap) = copyBody()


when isMainModule:
  import bytes
  import nimcrypto except toHex

  proc sha256s*(data: openarray[byte]): array[32, byte] {.inline.} =
    sha256.digest(data).data

  #const DISABLE_HASHTABLEDATA_DELETE = false
  proc empty*(pair: HashTableData): bool = pair.val == -1
  proc setEmpty*(pair: HashTableData) = pair.val = -1
  loadHashTableModules()

  proc `$`(data: array[32, byte]): string = data.toBytes.toHex

  var hashTable = newHashTable[array[32, byte], int](30)

  for i in 0..<20:
    hashTable.set(sha256s(i.toBytes), i)

  for i in 0..<20:
    if i mod 2 == 0:
      hashTable.del(sha256s(i.toBytes))

  for i in 0..<20:
    var pair = hashTable.get(sha256s(i.toBytes))
    if not pair.isNil and pair.val == i:
      echo i, " OK ", pair.key
    else:
      if i mod 2 == 0:
        echo i, " OK deleted"
      else:
        echo i, " Error"

  echo "dataCount=", hashTable.dataCount, " bitmapCount=", hashTable.countBitmap()

  var hashTable2 = newHashTable[array[32, byte], int](hashTable.dataCount * 3 div 2)
  echo "hashTable2.dataLen=", hashTable2.dataLen
  hashTable.copy(hashTable2)

  for i in 0..<20:
    hashTable.set(sha256s(i.toBytes), i)

  for i in 0..<20:
    var pair = hashTable.get(sha256s(i.toBytes))
    if not pair.isNil and pair.val == i:
      echo i, " OK ", pair.key
    else:
      echo i, " Error"

  echo "dataCount=", hashTable.dataCount, " bitmapCount=", hashTable.countBitmap()

  for i in 0..<20:
    var pair = hashTable2.get(sha256s(i.toBytes))
    if not pair.isNil and pair.val == i:
      echo i, " OK ", pair.key
    else:
      if i mod 2 == 0:
        echo i, " OK deleted"
      else:
        echo i, " Error"

  hashTable2.delete()
  hashTable.delete()
