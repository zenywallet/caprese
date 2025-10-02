# Copyright (c) 2022 zenywallet

when defined(ARRAY_USE_SEQ):
  import sequtils

  type
    Array*[T] = seq[T]

  template newArray*[T](len: Natural): Array[T] = newSeq[T](len)

  template newArray*[T](a: var Array[T], len: Natural) = newSeq(a, len)

  template newArrayUninitialized*[T](len: Natural): Array[T] = newSeqUninitialized[T](len)

  template newArrayOfCap*[T](len: Natural): Array[T] = newSeqOfCap[T](len)

  proc newArray*[T](buf: ptr UncheckedArray[T], len: Natural): Array[T] =
    result.newSeq(len)
    copyMem(addr result[0], buf, sizeof(T) * len)

  template toArray*[T](x: openArray[T]): Array[T] = toSeq(x)

  template toArray*[T](x: seq[T]): Array[T] = x

  template `@^`*[IDX, T](a: sink array[IDX, T]): Array[T] = @a

  template `@^`*[T](a: sink seq[T]): Array[T] = @a

else:
  type
    Array*[T] = object
      len*, cap*: int
      data*: ptr UncheckedArray[T]

  when NimMajor >= 2:
    when compileOption("mm", "orc") or
        compileOption("mm", "arc") or
        compileOption("mm", "atomicArc"):
      proc `=destroy`*[T](x: Array[T]) {.enforceNoRaises.} =
        if x.data != nil:
          when T is not Ordinal and T is not ptr and T is not pointer:
            for i in 0..<x.len:
              `=destroy`(x.data[i])
          x.data.deallocShared()
    else:
      proc `=destroy`*[T](x: var Array[T]) =
        if x.data != nil:
          when T is not Ordinal and T is not ptr and T is not pointer:
            for i in 0..<x.len:
              `=destroy`(x.data[i])
          x.data.deallocShared()
  else:
    proc `=destroy`*[T](x: var Array[T]) =
      if x.data != nil:
        when T is not Ordinal and T is not ptr and T is not pointer:
          for i in 0..<x.len:
            `=destroy`(x.data[i])
        x.data.deallocShared()

  proc `=copy`*[T](a: var Array[T]; b: Array[T]) =
    if a.data == b.data: return
    `=destroy`(a)
    wasMoved(a)
    a.len = b.len
    a.cap = b.cap
    if b.data != nil:
      a.data = cast[typeof(a.data)](allocShared0(sizeof(T) * a.cap))
      when T is Ordinal or T is ptr or T is pointer:
        copyMem(a.data, b.data, sizeof(T) * a.len)
      else:
        for i in 0..<a.len:
          a.data[i] = b.data[i]

  proc `=sink`*[T](a: var Array[T]; b: Array[T]) =
    `=destroy`(a)
    wasMoved(a)
    a.len = b.len
    a.cap = b.cap
    a.data = b.data

  template nextCap(cap: int): int =
    if cap <= 16:
      32
    else:
      cap * 2

  proc add*[T](x: var Array[T]; y: sink Array[T]) =
    let newLen = x.len + y.len
    if x.cap < newLen:
      x.cap = nextCap(newLen)
      x.data = cast[ptr UncheckedArray[T]](reallocShared0(x.data, sizeof(T) * x.len, sizeof(T) * x.cap))
    copyMem(addr x.data[x.len], addr y.data[0], sizeof(T) * y.len)
    x.len = newLen

  proc add*[T](x: var Array[T]; y: sink T) =
    let newLen = x.len + 1
    if x.cap < newLen:
      x.cap = nextCap(newLen)
      x.data = cast[ptr UncheckedArray[T]](reallocShared0(x.data, sizeof(T) * x.len, sizeof(T) * x.cap))
    x.data[x.len] = y
    x.len = newLen

  proc add*[T](x: var Array[T]; y: sink seq[T]) =
    let newLen = x.len + y.len
    if x.cap < newLen:
      x.cap = nextCap(newLen)
      x.data = cast[ptr UncheckedArray[T]](reallocShared0(x.data, sizeof(T) * x.len, sizeof(T) * x.cap))
    copyMem(addr x.data[x.len], unsafeAddr y[0], sizeof(T) * y.len)
    x.len = newLen

  proc add*[T](x: var Array[T]; y: sink openArray[T]) =
    let newLen = x.len + y.len
    if x.cap < newLen:
      x.cap = nextCap(newLen)
      x.data = cast[ptr UncheckedArray[T]](reallocShared0(x.data, sizeof(T) * x.len, sizeof(T) * x.cap))
    copyMem(addr x.data[x.len], unsafeAddr y[0], sizeof(T) * y.len)
    x.len = newLen

  template `[]`*[T](x: Array[T]; i: Natural): T =
    #assert 0 <= i and i < x.len
    x.data[i]

  template `[]`*[T](x: ptr Array[T]; i: Natural): T =
    #assert 0 <= i and i < x[].len
    x[].data[i]

  template `[]=`*[T](x: var Array[T]; i: Natural; y: sink T) =
    #assert 0 <= i and i < x.len
    x.data[i] = y

  proc len*[T](x: Array[T]): int {.inline.} = x.len

  proc newArray*[T](len: Natural): Array[T] =
    result.data = cast[typeof(result.data)](allocShared0(sizeof(T) * len))
    result.len = len
    result.cap = len

  proc newArray*[T](a: var Array[T], len: Natural) =
    a.data = cast[typeof(a.data)](allocShared0(sizeof(T) * len))
    a.len = len
    a.cap = len

  proc newArrayUninitialized*[T](len: Natural): Array[T] =
    result.data = cast[typeof(result.data)](allocShared(sizeof(T) * len))
    result.len = len
    result.cap = len

  proc newArrayUninitialized*[T](a: var Array[T], len: Natural): Array[T] =
    a.data = cast[typeof(a.data)](allocShared(sizeof(T) * len))
    a.len = len
    a.cap = len

  proc newArrayOfCap*[T](len: Natural): Array[T] =
    result.data = cast[typeof(result.data)](allocShared0(sizeof(T) * len))
    result.len = 0
    result.cap = len

  proc newArrayOfCap*[T](a: var Array[T], len: Natural) =
    a.data = cast[typeof(a.data)](allocShared0(sizeof(T) * len))
    a.len = 0
    a.cap = len

  proc newArray*[T](buf: ptr UncheckedArray[T], len: Natural): Array[T] =
    when T is Ordinal or T is ptr or T is pointer:
      let size = sizeof(T) * len
      result.data = cast[typeof(result.data)](allocShared0(size))
      copyMem(result.data, buf, size)
    else:
      result.data = cast[typeof(result.data)](allocShared0(sizeof(T) * len))
      for i in 0..<len:
        result.data[i] = buf[i]
    result.len = len
    result.cap = len

  proc toArray*[T](x: openArray[T]): Array[T] =
    if x.len > 0:
      when T is Ordinal or T is ptr or T is pointer:
        let size = sizeof(T) * x.len
        result.data = cast[typeof(result.data)](allocShared0(size))
        copyMem(result.data, unsafeAddr x[0], size)
      else:
        result.data = cast[typeof(result.data)](allocShared0(sizeof(T) * x.len))
        for i in 0..<x.len:
          result.data[i] = x[i]
      result.len = x.len
      result.cap = x.len

  proc toArray*[T](x: seq[T]): Array[T] =
    if x.len > 0:
      when T is Ordinal or T is ptr or T is pointer:
        let size = sizeof(T) * x.len
        result.data = cast[typeof(result.data)](allocShared0(size))
        copyMem(result.data, unsafeAddr x[0], size)
      else:
        result.data = cast[typeof(result.data)](allocShared0(sizeof(T) * x.len))
        for i in 0..<x.len:
          result.data[i] = x[i]
      result.len = x.len
      result.cap = x.len

  proc toSeq*[T](x: Array[T]): seq[T] =
    result.newSeq(x.len)
    for i in 0..<x.len:
      result[i] = x[i]

  proc `$`*[T](a: Array[T]): string =
    if a.len > 0:
      when T is string:
        result = "@^[\"" & $a[0]
        for i in 1..<a.len:
          result.add("\", \"" & $a[i])
        result.add("\"]")
      else:
        result = "@^[" & $a[0]
        for i in 1..<a.len:
          result.add(", " & $a[i])
        result.add("]")
    else:
      result = "@^[]"

  proc toHex*[T](a: Array[T]): string = a.toBytes.toHex

  iterator items*[T](a: Array[T]): lent T =
    for i in 0..<a.len:
      yield a.data[i]

  iterator pairs*[T](a: Array[T]): tuple[key: int, val: lent T] =
    for i in 0..<a.len:
      yield (i, a.data[i])

  proc high*[T](x: Array[T]): int {.inline.} = x.len - 1

  proc low*[T](x: Array[T]): int {.inline.} = 0

  proc `@^`*[IDX, T](a: sink array[IDX, T]): Array[T] =
    result.newArray(a.len)
    for i in 0..a.len-1:
      result[i] = a[i]

  proc `@^`*[T](a: sink seq[T]): Array[T] =
    result.newArray(a.len)
    for i in 0..a.len-1:
      result[i] = a[i]

  proc concat*[T](arrays: varargs[Array[T]]): Array[T] =
    var allLen = 0
    for a in arrays:
      inc(allLen, a.len)
    result.newArray(allLen)
    var i = 0
    for a in arrays:
      for item in a:
        result[i] = item
        inc(i)

  proc concat*[T](arrays: Array[Array[T]]): Array[T] =
    var allLen = 0
    for a in arrays:
      inc(allLen, a.len)
    result.newArray(allLen)
    var i = 0
    for a in arrays:
      for item in a:
        result[i] = item
        inc(i)

  proc `[]`*[T](a: Array[T]; i: BackwardsIndex): T {.inline.} =
    a[a.len - int(i) + low(a)]

  proc `[]`*[T](a: var Array[T]; i: BackwardsIndex): var T {.inline.} =
    a[a.len - int(i) + low(a)]

  proc `[]`*[T; U, V: Ordinal](a: Array[T]; x: HSlice[U, V]): Array[T] =
    var xa, xb: int
    when x.a is BackwardsIndex:
      xa = a.len - x.a.int
    else:
      xa = x.a.int
    when x.b is BackwardsIndex:
      xb = a.len - x.b.int
    else:
      xb = x.b.int
    let len = xb - xa + 1
    result.newArray(len)
    var idx = 0
    for i in xa..xb:
      result[idx] = a[i]
      inc(idx)

  proc empty*[T](x: var Array[T]) =
    `=destroy`(x)
    x.data = nil
    x.len = 0
    x.cap = 0

  proc clear*[T](x: var Array[T]) {.inline.} =
    x.len = 0

  proc del*[T](x: var Array[T]; i: Natural) =
    let last = x.high
    x[i] = x[last]
    x.len = last

  proc delete*[T](x: var Array[T]; i: Natural) =
    let last = x.high
    if i != last:
      moveMem(addr x[i], addr x[i + 1], last - i)
    x.len = last

  proc `==`*[T](x: Array[T] or seq[T], y: Array[T]): bool =
    if x.len != y.len:
      return false
    for f in x.low..x.high:
      if x[f] != y[f]:
        return false
    result = true

  template `==`*[T](x: Array[T], y: seq[T]): bool = `==`(y, x)

  proc setLen*[T](x: var Array[T], newLen: Natural) =
    if x.cap < newLen:
      x.cap = nextCap(newLen)
      x.data = cast[ptr UncheckedArray[T]](reallocShared0(x.data, sizeof(T) * x.len, sizeof(T) * x.cap))
    x.len = newlen

  proc toString*(x: Array[byte] or Array[char]): string =
    let xlen = len(x)
    result = newString(xlen)
    copyMem(addr result[0], x.data, xlen)
