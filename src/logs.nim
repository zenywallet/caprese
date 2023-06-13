# Copyright (c) 2022 zenywallet

import strutils

{.used.}

template debugBlock*(body: untyped) =
  when defined(DEBUG_LOG):
    body
  else:
    discard

template debug*(x: varargs[string, `$`]) =
  debugBlock:
    echo join(x)

template error*(x: varargs[string, `$`]) = echo join(x)

template errorException*(x: varargs[string, `$`], ex: typedesc) =
  let msg = join(x)
  echo msg
  raise newException(ex, msg)
