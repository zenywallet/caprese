# Copyright (c) 2021 zenywallet

import os
import zip/zlib

when isMainModule:
  if paramCount() >= 2:
    var srcFile = paramStr(1)
    var destFile = paramStr(2)
    var data = readFile(srcFile)
    var deflate = compress(data, stream = RAW_DEFLATE)
    writeFile(destFile, deflate)
