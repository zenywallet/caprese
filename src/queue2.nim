# Copyright (c) 2022 zenywallet

import macros

type
  Queue*[T] = object
    buf*: ptr UncheckedArray[T]
    bufLen*: int
    pos*: int
    next*: int
    accessId: int

  QueueEmptyError* = object of CatchableError
  QueueFullError* = object of CatchableError

const QueueFullErrorMessage = "queue is full"
const QueueEmptyErrorMessage = "no data"


proc atomic_compare_exchange_n(p: ptr int, expected: ptr int, desired: int, weak: bool,
                              success_memmodel: int, failure_memmodel: int): bool
                              {.importc: "__atomic_compare_exchange_n", nodecl, discardable.}

proc `=destroy`*[T](queue: var Queue[T]) =
  if likely(not queue.buf.isNil):
    queue.buf.deallocShared()
    queue.buf = nil

proc `=copy`*[T](a: var Queue[T]; b: Queue[T]) {.error: "=copy is not supported".}

proc `=sink`*[T](a: var Queue[T]; b: Queue[T]) {.error: "=sink is not supported".}

template clear*[T](queue: var Queue[T]) =
  queue.pos = 0
  queue.next = 0

proc init*[T](queue: var Queue[T], limit: int) {.inline.} =
  if unlikely(not queue.buf.isNil):
    `=destroy`(queue)

  let bufLen = limit + 1
  queue.buf = cast[ptr UncheckedArray[T]](allocShared0(sizeof(T) * bufLen))
  queue.bufLen = bufLen
  queue.clear()

proc newQueue*[T](limit: int): Queue[T] = result.init(limit)

proc add*[T](queue: var Queue[T], data: T) {.inline.} =
  queue.buf[queue.next] = data
  let next = queue.next + 1
  if unlikely(next >= queue.bufLen):
    if unlikely(queue.pos == 0):
      raise newException(QueueFullError, QueueFullErrorMessage)
    else:
      queue.next = 0
  elif unlikely(queue.pos == next):
    raise newException(QueueFullError, QueueFullErrorMessage)
  else:
    queue.next = next

proc pop*[T](queue: var Queue[T]): T {.inline.} =
  when not (T is ptr) and not (T is pointer):
    if likely(queue.pos != queue.next):
      result = queue.buf[queue.pos]
      if unlikely(queue.pos + 1 >= queue.bufLen):
        queue.pos = 0
      else:
        inc(queue.pos)
    else:
      raise newException(QueueEmptyError, QueueEmptyErrorMessage)
  else:
    if likely(queue.pos != queue.next):
      result = queue.buf[queue.pos]
      if unlikely(queue.pos + 1 >= queue.bufLen):
        queue.pos = 0
      else:
        inc(queue.pos)

proc addSafe*[T](queue: var Queue[T], data: T, accessId: static int) {.inline.} =
  while true:
    var expectedAccessId = 0
    if atomic_compare_exchange_n(addr queue.accessId, addr expectedAccessId, accessId, false, 0, 0):
      break

  queue.buf[queue.next] = data
  let next = queue.next + 1
  if unlikely(next >= queue.bufLen):
    if unlikely(queue.pos == 0):
      queue.accessId = 0
      raise newException(QueueFullError, QueueFullErrorMessage)
    else:
      queue.next = 0
  elif unlikely(queue.pos == next):
    queue.accessId = 0
    raise newException(QueueFullError, QueueFullErrorMessage)
  else:
    queue.next = next
  queue.accessId = 0

proc popSafe*[T](queue: var Queue[T], accessId: static int): T {.inline.} =
  while true:
    var expectedAccessId = 0
    if atomic_compare_exchange_n(addr queue.accessId, addr expectedAccessId, accessId, false, 0, 0):
      break

  when not (T is ptr) and not (T is pointer):
    if likely(queue.pos != queue.next):
      result = queue.buf[queue.pos]
      if unlikely(queue.pos + 1 >= queue.bufLen):
        queue.pos = 0
      else:
        inc(queue.pos)
    else:
      queue.accessId = 0
      raise newException(QueueEmptyError, QueueEmptyErrorMessage)
  else:
    if likely(queue.pos != queue.next):
      result = queue.buf[queue.pos]
      if unlikely(queue.pos + 1 >= queue.bufLen):
        queue.pos = 0
      else:
        inc(queue.pos)
  queue.accessId = 0

var curAccessId {.compileTime.} = 0

macro createAccessId(): int =
  inc(curAccessId)
  quote do: `curAccessId`

template addSafe*[T](queue: var Queue[T], data: T) = queue.addSafe(data, createAccessId())

template popSafe*[T](queue: var Queue[T]): T = queue.popSafe(createAccessId())
