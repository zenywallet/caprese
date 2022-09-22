# Copyright (c) 2022 zenywallet

import strutils

template debug*(x: varargs[string, `$`]) =
  when defined(DEBUG_LOG):
    echo join(x)
  else:
    discard

template error*(x: varargs[string, `$`]) = echo join(x)

template errorException*(x: varargs[string, `$`], ex: typedesc) =
  let msg = join(x)
  echo msg
  raise newException(ex, msg)
