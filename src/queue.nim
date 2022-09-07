# Copyright (c) 2022 zenywallet

const INITIAL_BUF_LEN = 128

type
  Queue*[T] = object
    buf*: ptr UncheckedArray[T]
    bufLen*: int
    count*: int
    next*: int

  QueueError* = object of CatchableError


proc add*[T](queue: var Queue[T], data: T) =
  if queue.count >= queue.bufLen:
    if queue.bufLen == 0:
      queue.buf = cast[ptr UncheckedArray[T]](allocShared0(sizeof(T) * INITIAL_BUF_LEN))
      queue.bufLen = INITIAL_BUF_LEN
    else:
      let prevLen = queue.bufLen
      let nextLen = queue.bufLen * 2
      queue.buf = cast[ptr UncheckedArray[T]](reallocShared(queue.buf, sizeof(T) * nextLen))
      var pos = queue.next - queue.count
      if pos < 0:
        let copyLen = pos.abs
        pos = pos + prevLen
        copyMem(addr queue.buf[nextLen - copyLen], addr queue.buf[pos], sizeof(T) * copyLen)
      queue.bufLen = nextLen
  elif queue.next >= queue.bufLen:
    queue.next = 0
  queue.buf[queue.next] = data
  inc(queue.count)
  inc(queue.next)

proc pop*[T](queue: var Queue[T]): T =
  if queue.count > 0:
    var pos = queue.next - queue.count
    if pos < 0:
      pos = pos + queue.bufLen
    dec(queue.count)
    result = queue.buf[pos]
  else:
    when not (T is ptr) and not (T is pointer):
      raise newException(QueueError, "no data")

iterator pop*[T](queue: var Queue[T]): lent T =
  while queue.count > 0:
    var pos = queue.next - queue.count
    if pos < 0:
      pos = pos + queue.bufLen
    dec(queue.count)
    yield queue.buf[pos]

proc clear*[T](queue: var Queue[T]) =
  if not queue.buf.isNil:
    queue.buf.deallocShared()
    queue.buf = nil
  queue.bufLen = 0
  queue.count = 0
  queue.next = 0

proc `=destroy`[T](queue: var Queue[T]) =
  if not queue.buf.isNil:
    queue.buf.deallocShared()
    queue.buf = nil

proc `=copy`*[T](a: var Queue[T]; b: Queue[T]) =
  if a.buf == b.buf: return
  `=destroy`(a)
  wasMoved(a)
  a.bufLen = b.bufLen
  a.count = b.count
  a.next = b.next
  if b.buf != nil:
    a.buf = cast[ptr UncheckedArray[T]](allocShared(sizeof(T) * a.bufLen))
    copyMem(a.buf, b.buf, sizeof(T) * a.bufLen)

proc `=sink`*[T](a: var Queue[T]; b: Queue[T]) =
  `=destroy`(a)
  wasMoved(a)
  a.bufLen = b.bufLen
  a.count = b.count
  a.next = b.next
  a.buf = b.buf


when isMainModule:
  var queue: Queue[int]

  var j = 0
  var k = 0

  for i in 0..<5000:
    queue.add(j); inc(j)
    queue.add(j); inc(j)
    queue.add(j); inc(j)
    assert queue.pop() == k; inc(k)

  var queue2 = queue #=copy
  var queue3: Queue[int]
  queue2 = queue3 #=sink

  for i in 5000..<10000:
    queue.add(j); inc(j)
    assert queue.pop() == k; inc(k)
    assert queue.pop() == k; inc(k)

  for p in queue.pop():
    assert p == k; inc(k)

  queue.clear(); k = j
