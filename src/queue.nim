# Copyright (c) 2022 zenywallet

import locks

type
  Queue*[T] = object
    buf*: ptr UncheckedArray[T]
    bufLen*: int
    count*: int
    next*: int
    lock: Lock

  QueueError* = object of CatchableError
  QueueEmptyError* = object of CatchableError
  QueueFullError* = object of CatchableError

proc init*[T](queue: var Queue[T], limit: int) =
  if not queue.buf.isNil:
    raise newException(QueueError, "already initialized")
  initLock(queue.lock)
  queue.buf = cast[ptr UncheckedArray[T]](allocShared0(sizeof(T) * limit))
  queue.bufLen = limit

proc add*[T](queue: var Queue[T], data: T) =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  if queue.count >= queue.bufLen:
    raise newException(QueueFullError, "queue is full")
  elif queue.next >= queue.bufLen:
    queue.next = 0
  queue.buf[queue.next] = data
  inc(queue.count)
  inc(queue.next)

proc pop*[T](queue: var Queue[T]): T =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  if queue.count > 0:
    var pos = queue.next - queue.count
    if pos < 0:
      pos = pos + queue.bufLen
    dec(queue.count)
    result = queue.buf[pos]
  else:
    when not (T is ptr) and not (T is pointer):
      raise newException(QueueEmptyError, "no data")

iterator pop*[T](queue: var Queue[T]): lent T =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  while queue.count > 0:
    var pos = queue.next - queue.count
    if pos < 0:
      pos = pos + queue.bufLen
    dec(queue.count)
    yield queue.buf[pos]

proc clear*[T](queue: var Queue[T]) =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  queue.count = 0
  queue.next = 0

proc `=destroy`[T](queue: var Queue[T]) =
  if not queue.buf.isNil:
    queue.buf.deallocShared()
    queue.buf = nil
    deinitLock(queue.lock)

proc `=copy`*[T](a: var Queue[T]; b: Queue[T]) =
  raise newException(QueueError, "=copy")

proc `=sink`*[T](a: var Queue[T]; b: Queue[T]) =
  raise newException(QueueError, "=sink")


when isMainModule:
  var queue: Queue[int]
  queue.init(100)

  proc setter(id: int) {.thread.} =
    var i = 0
    while true:
      try:
        queue.add(id * 10000 + i)
        inc(i)
        if i == 1000:
          break
      except:
        discard

  proc getter() {.thread.} =
    var i = 0
    while true:
      try:
        discard queue.pop()
        inc(i)
        if i == 1000:
          break
      except:
        discard

  var getterThreads: array[10, Thread[void]]
  for i in 0..<getterThreads.len:
    createThread(getterThreads[i], getter)

  var setterThreads: array[10, Thread[int]]
  for i in 0..<setterThreads.len:
    createThread(setterThreads[i], setter, i)

  joinThreads(setterThreads)
  joinThreads(getterThreads)

  echo queue.count
