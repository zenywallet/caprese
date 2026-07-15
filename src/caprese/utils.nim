# Copyright (c) 2026 zenywallet

import std/macros

macro doMacro*(body: untyped): untyped =
  var doMacro = genSym(nskMacro, "doMacro")
  quote do:
    macro `doMacro`(): untyped = `body`
    `doMacro`()
