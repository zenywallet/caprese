# Copyright (c) 2022 zenywallet

import os
import random

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

if paramCount() == 1:
  if paramStr(1) == "randomstr":
    var r = initRand()
    var res = newString(13)
    for i in 0..<res.len:
      res[i] = r.sample(letters)
    echo res

elif paramCount() == 2:
  if paramStr(1) == "rmfile":
    removeFile(paramStr(2))
    echo "rm ", paramStr(2)
