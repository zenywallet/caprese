# Copyright (c) 2022 zenywallet

import macros
import locks

type
  Queue*[T] = object
    buf*: ptr UncheckedArray[T]
    bufLen*: int
    pos*: int
    next*: int
    addLock: Lock
    popLock: Lock
    cond: Cond


proc `=destroy`*[T](queue: var Queue[T]) =
  if likely(not queue.buf.isNil):
    queue.buf.deallocShared()
    queue.buf = nil
    deinitLock(queue.addLock)
    deinitLock(queue.popLock)
    deinitCond(queue.cond)

proc `=copy`*[T](a: var Queue[T]; b: Queue[T]) {.error: "=copy is not supported".}

proc `=sink`*[T](a: var Queue[T]; b: Queue[T]) {.error: "=sink is not supported".}

template clear*[T](queue: var Queue[T]) =
  queue.pos = -1
  queue.next = -1

proc init*[T](queue: var Queue[T], limit: int) {.inline.} =
  when not (T is ptr) and not (T is pointer): {.error: "T must be a pointer".}

  if unlikely(not queue.buf.isNil):
    `=destroy`(queue)

  initCond(queue.cond)
  initLock(queue.popLock)
  initLock(queue.addLock)
  queue.buf = cast[ptr UncheckedArray[T]](allocShared0(sizeof(T) * limit))
  queue.bufLen = limit
  queue.clear()

proc newQueue*[T](limit: int): Queue[T] = result.init(limit)

proc add*[T](queue: var Queue[T], data: T): bool {.discardable, inline.} =
  let next = queue.next + 1
  if unlikely(next >= queue.bufLen):
    if unlikely(queue.pos == 0):
      return false
    else:
      queue.buf[0] = data
      queue.next = 0
  elif unlikely(queue.pos == next):
    return false
  else:
    queue.buf[next] = data
    queue.next = next
  return true

proc pop*[T](queue: var Queue[T]): T {.inline.} =
  let pos = queue.pos + 1
  if unlikely(pos >= queue.bufLen):
    if unlikely(queue.next != 0):
      result = queue.buf[0]
      queue.pos = 0
  elif unlikely(pos != queue.next):
    result = queue.buf[pos]
    queue.pos = pos

proc addSafe*[T](queue: var Queue[T], data: T): bool {.discardable, inline.} =
  acquire(queue.addLock)
  let next = queue.next + 1
  if unlikely(next >= queue.bufLen):
    if unlikely(queue.pos == 0):
      release(queue.addLock)
      return false
    else:
      queue.buf[0] = data
      queue.next = 0
  elif unlikely(queue.pos == next):
    release(queue.addLock)
    return false
  else:
    queue.buf[next] = data
    queue.next = next
  release(queue.addLock)
  return true

proc popSafe*[T](queue: var Queue[T]): T {.inline.} =
  acquire(queue.popLock)
  let pos = queue.pos + 1
  if unlikely(pos >= queue.bufLen):
    if unlikely(queue.next != 0):
      result = queue.buf[0]
      queue.pos = 0
  elif unlikely(pos != queue.next):
    result = queue.buf[pos]
    queue.pos = pos
  release(queue.popLock)

proc send*[T](queue: var Queue[T], data: T) {.inline.} =
  queue.add(data)
  signal(queue.cond)
  # warning: signal may miss and need to be resolved elsewhere

proc recv*[T](queue: var Queue[T]): T {.inline.} =
  acquire(queue.popLock)
  while true:
    result = queue.pop()
    if not result.isNil: break
    wait(queue.cond, queue.popLock)
  release(queue.popLock)
