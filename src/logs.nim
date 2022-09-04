# Copyright (c) 2022 zenywallet

template debug*(x: varargs[string, `$`]) =
  when defined(DEBUG_LOG):
    echo join(x)
  else:
    discard
