# Copyright (c) 2021 zenywallet

import posix

template debug(x: varargs[string, `$`]) =
  when declared(DEBUG_LOG):
    echo join(x)
  else:
    discard

proc setRlimitOpenFiles*(rlim: int): bool {.discardable.} =
  var rlp: RLimit
  var ret = getrlimit(RLIMIT_NOFILE, rlp)
  if ret != 0: return false
  debug "RLIMIT_NOFILE prev=", rlp
  if rlp.rlim_cur < rlim:
    if rlp.rlim_max < rlim:
      rlp.rlim_cur = rlp.rlim_max
    else:
      rlp.rlim_cur = rlim
    ret = setrlimit(RLIMIT_NOFILE, rlp)
    if ret != 0: return false
  else:
    debug "RLIMIT_NOFILE cur=", rlp
    return true
  ret = getrlimit(RLIMIT_NOFILE, rlp)
  if ret != 0: return false
  debug "RLIMIT_NOFILE new=", rlp
  if rlp.rlim_cur < rlim: return false
  return true
