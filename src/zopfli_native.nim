# Copyright (c) 2020 zenywallet

import os

const zopfliPath = currentSourcePath().parentDir() / "../deps/zopfli"

{.passC: "-I\"" & zopfliPath / "src/zopfli" & "\"".}
{.compile: zopfliPath / "src/zopfli/deflate.c".}
{.compile: zopfliPath / "src/zopfli/blocksplitter.c".}
{.compile: zopfliPath / "src/zopfli/squeeze.c".}
{.compile: zopfliPath / "src/zopfli/tree.c".}
{.compile: zopfliPath / "src/zopfli/lz77.c".}
{.compile: zopfliPath / "src/zopfli/hash.c".}
{.compile: zopfliPath / "src/zopfli/katajainen.c".}
{.compile: zopfliPath / "src/zopfli/cache.c".}

{.emit: """
#include "deflate.h"

static ZopfliOptions options = { 0, 0, 15, 1, 0, 15 };

void zopfli_comp(const unsigned char* in, size_t insize, unsigned char** out, size_t* outsize) {
  unsigned char bp = 0;
  ZopfliDeflate(&options, 2, 1, in, insize, &bp, out, outsize);
}

void zopfli_free(void *ptr) {
  free(ptr);
}
""".}

proc zopfli_comp*(inbuf: ptr uint8; insize: csize_t; outbuf: ptr ptr uint8; outsize: ptr csize_t) {.importc.}
proc zopfli_free*(p: pointer) {.importc.}
