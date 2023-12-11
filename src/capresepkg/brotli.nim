# Copyright (c) 2020 zenywallet

import os

const brotliPath = currentSourcePath().parentDir() / "../brotli"

{.passC: "-I\"" & brotliPath / "c/include" & "\"".}
{.passL: "-lm".}

{.compile: brotliPath / "c/enc/backward_references.c".}
{.compile: brotliPath / "c/enc/backward_references_hq.c".}
{.compile: brotliPath / "c/enc/bit_cost.c".}
{.compile: brotliPath / "c/enc/block_splitter.c".}
{.compile: brotliPath / "c/enc/brotli_bit_stream.c".}
{.compile: brotliPath / "c/enc/cluster.c".}
{.compile: brotliPath / "c/enc/command.c".}
{.compile: brotliPath / "c/enc/compound_dictionary.c".}
{.compile: brotliPath / "c/enc/compress_fragment.c".}
{.compile: brotliPath / "c/enc/compress_fragment_two_pass.c".}
{.compile: brotliPath / "c/enc/dictionary_hash.c".}
{.compile: brotliPath / "c/enc/encode.c".}
{.compile: brotliPath / "c/enc/encoder_dict.c".}
{.compile: brotliPath / "c/enc/entropy_encode.c".}
{.compile: brotliPath / "c/enc/fast_log.c".}
{.compile: brotliPath / "c/enc/histogram.c".}
{.compile: brotliPath / "c/enc/literal_cost.c".}
{.compile: brotliPath / "c/enc/memory.c".}
{.compile: brotliPath / "c/enc/metablock.c".}
{.compile: brotliPath / "c/enc/static_dict.c".}
{.compile: brotliPath / "c/enc/utf8_util.c".}

{.compile: brotliPath / "c/common/constants.c".}
{.compile: brotliPath / "c/common/context.c".}
{.compile: brotliPath / "c/common/dictionary.c".}
{.compile: brotliPath / "c/common/platform.c".}
{.compile: brotliPath / "c/common/shared_dictionary.c".}
{.compile: brotliPath / "c/common/transform.c".}

{.compile: brotliPath / "c/dec/bit_reader.c".}
{.compile: brotliPath / "c/dec/decode.c".}
{.compile: brotliPath / "c/dec/huffman.c".}
{.compile: brotliPath / "c/dec/state.c".}

type
  BrotliEncoderMode* = enum
    BROTLI_MODE_GENERIC = 0,    ## * Compression mode for UTF-8 formatted text input.
    BROTLI_MODE_TEXT = 1,       ## * Compression mode used in WOFF 2.0.
    BROTLI_MODE_FONT = 2

const
  BROTLI_DEFAULT_QUALITY* = 11

type
  BROTLI_BOOL* = int

const
  BROTLI_TRUE* = 1
  BROTLI_FALSE* = 0

type
  uint8_t = uint8

proc BrotliEncoderCompress*(quality: cint; lgwin: cint; mode: BrotliEncoderMode;
                            input_size: csize_t;
                            input_buffer: ptr UncheckedArray[uint8_t];
                            encoded_size: ptr csize_t;
                            encoded_buffer: ptr UncheckedArray[uint8_t]): BROTLI_BOOL {.importc.}
proc BrotliEncoderMaxCompressedSize*(input_size: csize_t): csize_t {.importc.}

type                          ## * Decoding error, e.g. corrupted input or memory allocation problem.
  BrotliDecoderResult* = enum
    BROTLI_DECODER_RESULT_ERROR = 0, ## * Decoding successfully completed.
    BROTLI_DECODER_RESULT_SUCCESS = 1, ## * Partially done; should be called again with more input.
    BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT = 2, ## * Partially done; should be called again with more output.
    BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3

proc BrotliDecoderDecompress*(encoded_size: csize_t,
                              encoded_buffer: ptr UncheckedArray[uint8_t];
                              decoded_size: ptr csize_t;
                              decoded_buffer: ptr UncheckedArray[uint8_t]): BrotliDecoderResult {.importc.}

type
  BrotliDecoderState* = object
  brotli_alloc_func* = proc (opaque: pointer; size: csize_t): pointer
  brotli_free_func* = proc (opaque: pointer; address: pointer)

proc BrotliDecoderCreateInstance*(alloc_func: pointer;
                                 free_func: pointer; opaque: pointer): ptr BrotliDecoderState {.importc.}
proc BrotliDecoderDestroyInstance*(state: ptr BrotliDecoderState) {.importc.}
proc BrotliDecoderIsFinished*(state: ptr BrotliDecoderState): BROTLI_BOOL {.importc.}
proc BrotliDecoderDecompressStream*(state: ptr BrotliDecoderState;
                                   available_in: ptr csize_t;
                                   next_in: ptr ptr UncheckedArray[uint8_t];
                                   available_out: ptr csize_t;
                                   next_out: ptr ptr UncheckedArray[uint8_t];
                                   total_out: ptr csize_t): BrotliDecoderResult {.importc.}
proc BrotliDecoderTakeOutput*(state: ptr BrotliDecoderState; size: ptr csize_t): ptr UncheckedArray[uint8_t] {.importc.}


proc comp*(in_buf: ptr UncheckedArray[byte], in_size: uint,
          out_buf: ptr ptr UncheckedArray[byte], out_size: ptr uint) {.exportc: "brotli_comp".} =
  var buf_size = BrotliEncoderMaxCompressedSize(in_size)
  var buf = cast[ptr UncheckedArray[uint8_t]](alloc0(buf_size))
  if not buf.isNil and
    BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, -1,
                          BrotliEncoderMode.BROTLI_MODE_GENERIC,
                          in_size, in_buf,
                          addr buf_size,
                          cast[ptr UncheckedArray[uint8_t]](addr buf[0])) == BROTLI_TRUE:
    out_buf[] = buf
    out_size[] = buf_size
  else:
    out_buf[] = nil
    out_size[] = 0

proc decomp*(in_buf: ptr UncheckedArray[byte], in_size: uint,
            out_buf: ptr ptr UncheckedArray[byte], out_size: ptr uint) {.exportc: "brotli_decomp".} =
  var decoder = BrotliDecoderCreateInstance(cast[pointer](nil), cast[pointer](nil), cast[pointer](nil))
  if not decoder.isNil:
    var buf_pos: csize_t = 0
    var buf_size: csize_t = 0
    var buf: ptr UncheckedArray[uint8_t]
    while decoder.BrotliDecoderIsFinished == BROTLI_FALSE:
      var input_size: csize_t = in_size
      var output_size: csize_t = 0
      var decRet = decoder.BrotliDecoderDecompressStream(addr input_size,
                                                        unsafeAddr in_buf,
                                                        cast[ptr csize_t](addr output_size),
                                                        cast[ptr ptr UncheckedArray[uint8_t]](nil), cast[ptr csize_t](nil))
      if decRet == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
        var takeOutput = decoder.BrotliDecoderTakeOutput(cast[ptr csize_t](addr output_size))
        if output_size == 0:
          break
        buf_size = buf_size + output_size
        if buf.isNil:
          buf = cast[ptr UncheckedArray[uint8_t]](alloc0(buf_size))
        else:
          buf = cast[ptr UncheckedArray[uint8_t]](buf.realloc(buf_size))
        out_buf[] = buf
        if buf.isNil:
          out_size[] = 0
          break
        copyMem(addr buf[buf_pos], addr takeOutput[0], output_size)
        buf_pos = buf_size
        out_size[] = buf_size
      else:
        if buf_size == 0:
          out_buf[] = nil
          out_size[] = 0
        break
    decoder.BrotliDecoderDestroyInstance()

proc free*(p: pointer) {.exportc: "brotli_free".} =
  dealloc(p)

proc comp*(data: seq[byte] | string): seq[byte] =
  var outBuf: ptr UncheckedArray[uint8_t]
  var outSize: csize_t
  brotli.comp(cast[ptr UncheckedArray[uint8_t]](unsafeAddr data[0]), data.len.uint, addr outBuf, addr outSize)
  var b = newSeqUninitialized[byte](outSize)
  copyMem(addr b[0], addr outBuf[0], outSize)
  brotli.free(outBuf)
  result = b

proc decomp*(data: seq[byte] | string): seq[byte] =
  var outBuf: ptr UncheckedArray[uint8_t]
  var outSize: csize_t
  brotli.decomp(cast[ptr UncheckedArray[uint8_t]](unsafeAddr data[0]), data.len.uint, addr outBuf, addr outSize)
  var b = newSeqUninitialized[byte](outSize)
  copyMem(addr b[0], addr outBuf[0], outSize)
  brotli.free(outBuf)
  result = b


when isMainModule:
  import bytes

  if paramCount() >= 2:
    var srcFile = paramStr(1)
    var destFile = paramStr(2)
    var data = readFile(srcFile)
    var brotliComp = brotli.comp(data)
    writeFile(destFile, brotliComp)

  else:
    var d1 = "hellohellohellohellohello"
    echo brotli.comp(d1)
    echo brotli.decomp(brotli.comp(d1)).toString

    var d2: seq[byte]
    for i in 1..10:
      for j in 1..10:
        d2.add(j.byte)
    echo brotli.comp(d2)
    echo brotli.decomp(brotli.comp(d2))
