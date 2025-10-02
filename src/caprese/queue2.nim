# Copyright (c) 2022 zenywallet

import std/macros
import std/locks

type
  Queue*[T] = object
    buf*: ptr UncheckedArray[T]
    bufLen*: int
    pos*: uint
    next*: uint
    addLock: Lock
    popLock: Lock
    cond: Cond

proc atomic_compare_exchange_n(p: ptr uint64, expected: ptr uint64, desired: uint64, weak: bool,
                              success_memmodel: int, failure_memmodel: int): bool
                              {.importc: "__atomic_compare_exchange_n", nodecl, discardable.}

#proc atomic_fetch_add(p: ptr uint64, val: uint64, memmodel: int): uint64
#                        {.importc: "__atomic_fetch_add", nodecl, discardable.}

#proc atomic_fetch_sub(p: ptr uint64, val: uint64, memmodel: int): uint64
#                        {.importc: "__atomic_fetch_sub", nodecl, discardable.}


when NimMajor >= 2:
  when compileOption("mm", "orc") or
      compileOption("mm", "arc") or
      compileOption("mm", "atomicArc"):
    proc `=destroy`*[T](queue: Queue[T]) =
      if likely(not queue.buf.isNil):
        queue.buf.deallocShared()
        deinitLock((unsafeAddr queue).addLock)
        deinitLock((unsafeAddr queue).popLock)
        deinitCond((unsafeAddr queue).cond)
  else:
    proc `=destroy`*[T](queue: var Queue[T]) =
      if likely(not queue.buf.isNil):
        queue.buf.deallocShared()
        queue.buf = nil
        deinitLock(queue.addLock)
        deinitLock(queue.popLock)
        deinitCond(queue.cond)
else:
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
  queue.pos = 0
  queue.next = 0

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

proc newQueue*[T](): Queue[T] = result.init(0x10000)

proc add*[T](queue: var Queue[T], data: T): bool {.discardable, inline.} =
  if cast[uint16](queue.next + 1) == cast[uint16](queue.pos):
    return false
  queue.buf[cast[uint16](queue.next)] = data
  inc(queue.next)
  return true

proc addSafe*[T](queue: var Queue[T], data: T): bool {.discardable, inline.} =
  acquire(queue.addLock)
  if cast[uint16](queue.next + 1) == cast[uint16](queue.pos):
    release(queue.addLock)
    return false
  queue.buf[cast[uint16](queue.next)] = data
  inc(queue.next)
  release(queue.addLock)
  return true

proc pop*[T](queue: var Queue[T]): T {.inline.} =
  var pos = queue.pos
  if cast[uint16](queue.pos) != cast[uint16](queue.next):
    if atomic_compare_exchange_n(cast[ptr uint64](addr queue.pos), cast[ptr uint64](addr pos),
                                cast[uint64](pos + 1), false, 0, 0):
      result = queue.buf[cast[uint16](pos)]

proc popUnsafe*[T](queue: var Queue[T]): T {.inline.} =
  if cast[uint16](queue.pos) != cast[uint16](queue.next):
      result = queue.buf[cast[uint16](queue.pos)]
      inc(queue.pos)

proc popSafe*[T](queue: var Queue[T]): T {.inline.} =
  acquire(queue.popLock)
  if cast[uint16](queue.pos) != cast[uint16](queue.next):
      result = queue.buf[cast[uint16](queue.pos)]
      inc(queue.pos)
  release(queue.popLock)

proc send*[T](queue: var Queue[T], data: T) {.inline.} =
  queue.add(data)
  signal(queue.cond)
  # warning: signal may miss and need to be resolved elsewhere

proc sendFlush*[T](queue: var Queue[T]) {.inline.} = signal(queue.cond)

proc recv*[T](queue: var Queue[T]): T {.inline.} =
  acquire(queue.popLock)
  while true:
    if cast[uint16](queue.pos) != cast[uint16](queue.next):
      result = queue.buf[cast[uint16](queue.pos)]
      inc(queue.pos)
      break
    wait(queue.cond, queue.popLock)
  release(queue.popLock)

proc recv*[T](queue: var Queue[T], waitCond: var bool): T {.inline.} =
  acquire(queue.popLock)
  while true:
    if cast[uint16](queue.pos) != cast[uint16](queue.next):
      result = queue.buf[cast[uint16](queue.pos)]
      inc(queue.pos)
      break
    if not waitCond:
      break
    wait(queue.cond, queue.popLock)
  release(queue.popLock)

proc count*[T](queue: var Queue[T]): int = cast[int](queue.next - queue.pos)
