# Copyright (c) 2021 zenywallet

import posix

type
  RWLock* = Pthread_rwlock
  SpinLock* = Pthread_spinlock

  PthreadLockError* = object of CatchableError


{.push stackTrace: off.}
proc rwlockInit*(a: var RWLock) =
  if pthread_rwlock_init(addr a, nil) != 0:
    raise newException(PthreadLockError, "pthread lock init")

proc rwlockDestroy*(a: var RWLock) =
  if pthread_rwlock_destroy(addr a) != 0:
    raise newException(PthreadLockError, "pthread lock destroy")

proc rdlock*(a: var RWLock) =
  if pthread_rwlock_rdlock(addr a) != 0:
    raise newException(PthreadLockError, "pthread rdlock")

proc wrlock*(a: var RWLock) =
  if pthread_rwlock_wrlock(addr a) != 0:
    raise newException(PthreadLockError, "pthread wrlock")

proc unlock*(a: var RWLock) =
  if pthread_rwlock_unlock(addr a) != 0:
    raise newException(PthreadLockError, "pthread unlock")

template withReadLock*(a: var RWLock, body: untyped) =
  if pthread_rwlock_rdlock(addr a) != 0:
    raise newException(PthreadLockError, "pthread rdlock")
  {.locks: [a].}:
    try:
      body
    finally:
      if pthread_rwlock_unlock(addr a) != 0:
        raise newException(PthreadLockError, "pthread unlock")

template withWriteLock*(a: var RWLock, body: untyped) =
  if pthread_rwlock_wrlock(addr a) != 0:
    raise newException(PthreadLockError, "pthread wrlock")
  {.locks: [a].}:
    try:
      body
    finally:
      if pthread_rwlock_unlock(addr a) != 0:
        raise newException(PthreadLockError, "pthread unlock")


proc spinLockInit*(a: var SpinLock, pshared: cint = PTHREAD_PROCESS_PRIVATE) =
  if pthread_spin_init(addr a, pshared) != 0:
    raise newException(PthreadLockError, "pthread spin lock init")

proc spinLockDestroy*(a: var SpinLock) =
  if pthread_spin_destroy(addr a) != 0:
    raise newException(PthreadLockError, "pthread spin lock destroy")

template spinLockAcquire*(a: var SpinLock) =
  discard pthread_spin_lock(addr a)

template spinLockRelease*(a: var SpinLock) =
  discard pthread_spin_unlock(addr a)

template initLock*(a: var SpinLock, pshared: cint = PTHREAD_PROCESS_PRIVATE) =
  discard pthread_spin_init(addr a, pshared)

template deinitLock*(a: var SpinLock) =
  discard pthread_spin_destroy(addr a)

template acquire*(a: var SpinLock) =
  discard pthread_spin_lock(addr a)

template release*(a: var SpinLock) =
  discard pthread_spin_unlock(addr a)

template withSpinLock*(a: var SpinLock, body: untyped) =
  if pthread_spin_lock(addr a) != 0:
    raise newException(PthreadLockError, "pthread spin lock")
  {.locks: [a].}:
    try:
      body
    finally:
      if pthread_spin_unlock(addr a) != 0:
        raise newException(PthreadLockError, "pthread spin unlock")
{.pop.}


when isMainModule:
  import os

  var rwLock: RWLock
  var spinLock: SpinLock

  rwlockInit(rwLock)
  spinLockInit(spinLock)

  var threads: array[2, Thread[int]]

  proc worker1(id: int) {.thread.} =
    withReadLock rwLock:
      echo id, " begin read"
      sleep(2000)
      echo id, " end read"

  proc worker2(id: int) {.thread.} =
    withWriteLock rwLock:
      echo id, " begin write"
      sleep(2000)
      echo id, " end write"

  proc worker3(id: int) {.thread.} =
    withSpinLock spinLock:
      echo id, " begin spin"
      sleep(2000)
      echo id, " end spin"

  for i in 0..1:
    createThread(threads[i], worker1, i)
  threads.joinThreads()

  for i in 0..1:
    createThread(threads[i], worker2, i)
  threads.joinThreads()

  for i in 0..1:
    createThread(threads[i], worker3, i)
  threads.joinThreads()

  spinLock.spinLockDestroy()
  rwLock.rwlockDestroy()
