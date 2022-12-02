# Copyright (c) 2022 zenywallet

import locks

type
  Queue*[T] = object
    buf*: ptr UncheckedArray[T]
    bufLen*: int
    count*: int
    next*: int
    cond: Cond
    lock: Lock
    waitCount: int

  QueueError* = object of CatchableError
  QueueEmptyError* = object of CatchableError
  QueueFullError* = object of CatchableError

proc init*[T](queue: var Queue[T], limit: int) =
  if unlikely(not queue.buf.isNil):
    raise newException(QueueError, "already initialized")
  initCond(queue.cond)
  initLock(queue.lock)
  queue.buf = cast[ptr UncheckedArray[T]](allocShared0(sizeof(T) * limit))
  queue.bufLen = limit

proc newQueue*[T](limit: int): Queue[T] = result.init(limit)

proc add*[T](queue: var Queue[T], data: T) =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  if unlikely(queue.count >= queue.bufLen):
    raise newException(QueueFullError, "queue is full")
  elif unlikely(queue.next >= queue.bufLen):
    queue.next = 0
  queue.buf[queue.next] = data
  inc(queue.count)
  inc(queue.next)

proc pop*[T](queue: var Queue[T]): T =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  if likely(queue.count > 0):
    var pos = queue.next - queue.count
    if unlikely(pos < 0):
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
  while likely(queue.count > 0):
    var pos = queue.next - queue.count
    if unlikely(pos < 0):
      pos = pos + queue.bufLen
    dec(queue.count)
    yield queue.buf[pos]

proc send*[T](queue: var Queue[T], data: T): bool {.discardable.} =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  if unlikely(queue.count >= queue.bufLen or queue.count < 0):
    return false
  elif unlikely(queue.next >= queue.bufLen):
    queue.next = 0
  queue.buf[queue.next] = data
  inc(queue.count)
  inc(queue.next)
  if unlikely(queue.waitCount > 0):
    signal(queue.cond)
  return true

proc recv*[T](queue: var Queue[T]): T =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  if unlikely(queue.count == 0):
    inc(queue.waitCount)
    while true:
      wait(queue.cond, queue.lock)
      if unlikely(queue.count == 0):
        continue
      else:
        dec(queue.waitCount)
        if likely(queue.count > 0):
          break
        else:
          return
  elif unlikely(queue.count < 0):
    return
  var pos = queue.next - queue.count
  if unlikely(pos < 0):
    pos = pos + queue.bufLen
  dec(queue.count)
  result = queue.buf[pos]

proc drop*[T](queue: var Queue[T]) =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  queue.count = -1
  var waitCount = queue.waitCount
  for _ in 0..<waitCount:
    signal(queue.cond)

proc clear*[T](queue: var Queue[T]) =
  acquire(queue.lock)
  defer:
    release(queue.lock)
  queue.count = 0
  queue.next = 0

proc `=destroy`[T](queue: var Queue[T]) =
  if likely(not queue.buf.isNil):
    queue.buf.deallocShared()
    queue.buf = nil
    deinitLock(queue.lock)
    deinitCond(queue.cond)

proc `=copy`*[T](a: var Queue[T]; b: Queue[T]) =
  raise newException(QueueError, "=copy")

proc `=sink`*[T](a: var Queue[T]; b: Queue[T]) =
  raise newException(QueueError, "=sink")


when isMainModule:
  import os

  var queue = newQueue[int](100)

  proc setter(id: int) {.thread.} =
    var i = 0
    while true:
      sleep(5)
      try:
        queue.send(id * 10000 + i)
        inc(i)
        if i == 1000:
          break
      except:
        discard

  proc getter() {.thread.} =
    var i = 0
    while true:
      try:
        echo queue.recv()
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
