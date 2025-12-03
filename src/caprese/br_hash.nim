# Copyright (c) 2025 zenywallet

import os

const bearsslPath = currentSourcePath().parentDir() / "deps/bearssl"

{.passC: "-I\"" & bearsslPath / "inc" & "\"".}
{.passC: "-I\"" & bearsslPath / "src" & "\"".}
{.compile: bearsslPath / "src/hash/sha2small.c".}
{.compile: bearsslPath / "src/codec/dec32be.c".}
{.compile: bearsslPath / "src/codec/enc32be.c".}
{.compile: bearsslPath / "src/hash/sha2big.c".}
{.compile: bearsslPath / "src/codec/dec64be.c".}
{.compile: bearsslPath / "src/codec/enc64be.c".}
{.compile: bearsslPath / "src/mac/hmac.c".}
{.compile: bearsslPath / "src/hash/sha1.c".}

type
  uint32_t = uint32
  uint64_t = uint64

type
  br_hash_class = br_hash_class_0
  br_hash_class_0 {.bycopy.} = object
    context_size: csize_t

type
  br_sha224_context {.bycopy.} = object
    vtable: ptr br_hash_class
    buf: array[64, uint8]
    count: uint64_t
    val: array[8, uint32_t]

const
  br_sha256_SIZE = 32

type
  br_sha256_context = br_sha224_context

proc br_sha224_update(ctx: ptr br_sha224_context; data: pointer; len: csize_t) {.importc, cdecl, gcsafe.}
proc br_sha256_init(ctx: ptr br_sha256_context) {.importc, cdecl, gcsafe.}
const
  br_sha256_update = br_sha224_update
proc br_sha256_out(ctx: ptr br_sha256_context; `out`: pointer) {.importc, cdecl, gcsafe.}

type
  br_sha384_context {.bycopy.} = object
    vtable: ptr br_hash_class
    buf: array[128, uint8]
    count: uint64_t
    val: array[8, uint64_t]

const
  br_sha512_SIZE = 64

type
  br_sha512_context = br_sha384_context

proc br_sha384_update(ctx: ptr br_sha384_context; data: pointer; len: csize_t) {.importc, cdecl, gcsafe.}
proc br_sha512_init(ctx: ptr br_sha512_context) {.importc, cdecl, gcsafe.}
const
  br_sha512_update = br_sha384_update
proc br_sha512_out(ctx: ptr br_sha512_context; `out`: pointer) {.importc, cdecl, gcsafe.}

proc sha256*(data: ptr UncheckedArray[byte], size: uint32): array[br_sha256_SIZE, byte] =
  var ctx: br_sha256_context
  br_sha256_init(addr ctx)
  br_sha256_update(addr ctx, data, size.csize_t)
  br_sha256_out(addr ctx, addr result)

proc sha512*(data: ptr UncheckedArray[byte], size: uint32): array[br_sha512_SIZE, byte] =
  var ctx: br_sha512_context
  br_sha512_init(addr ctx)
  br_sha512_update(addr ctx, data, size.csize_t)
  br_sha512_out(addr ctx, addr result)

var br_sha256_vtable {.importc.}: br_hash_class
var br_sha512_vtable {.importc.}: br_hash_class

type
  br_hmac_key_context {.bycopy.} = object
    dig_vtable: ptr br_hash_class
    ksi: array[64, uint8]
    kso: array[64, uint8]

proc br_hmac_key_init(kc: ptr br_hmac_key_context;
                      digest_vtable: ptr br_hash_class; key: pointer;
                      key_len: csize_t) {.importc, cdecl, gcsafe.}

type
  br_md5_context {.bycopy.} = object
    vtable: ptr br_hash_class
    buf: array[64, uint8]
    count: uint64_t
    val: array[4, uint32_t]

type
  br_sha1_context {.bycopy.} = object
    vtable: ptr br_hash_class
    buf: array[64, uint8]
    count: uint64_t
    val: array[5, uint32_t]

type
  br_md5sha1_context {.bycopy.} = object
    vtable: ptr br_hash_class
    buf: array[64, uint8]
    count: uint64_t
    val_md5: array[4, uint32_t]
    val_sha1: array[5, uint32_t]

type
  br_hash_compat_context {.bycopy, union.} = object
    vtable: ptr br_hash_class
    md5: br_md5_context
    sha1: br_sha1_context
    sha224: br_sha224_context
    sha256: br_sha256_context
    sha384: br_sha384_context
    sha512: br_sha512_context
    md5sha1: br_md5sha1_context

type
  br_hmac_context {.bycopy.} = object
    dig: br_hash_compat_context
    kso: array[64, uint8]
    out_len: csize_t

proc br_hmac_init(ctx: ptr br_hmac_context; kc: ptr br_hmac_key_context;
                  out_len: csize_t) {.importc, cdecl, gcsafe.}

proc br_hmac_update(ctx: ptr br_hmac_context; data: pointer; len: csize_t) {.importc, cdecl, gcsafe.}

proc br_hmac_out(ctx: ptr br_hmac_context; `out`: pointer): csize_t {.importc, cdecl, gcsafe.}

proc sha256Hmac*(key: ptr UncheckedArray[byte], keySize: uint32, data: ptr UncheckedArray[byte], dataSize: uint32): array[br_sha256_SIZE, byte] =
  var hmacKeyCtx: br_hmac_key_context
  var hmacCtx: br_hmac_context
  br_hmac_key_init(addr hmacKeyCtx, addr br_sha256_vtable, cast[pointer](key), keySize.csize_t)
  br_hmac_init(addr hmacCtx, addr hmacKeyCtx, br_sha256_SIZE.csize_t)
  br_hmac_update(addr hmacCtx, cast[pointer](data), dataSize.csize_t)
  discard br_hmac_out(addr hmacCtx, addr result)

proc sha512Hmac*(key: ptr UncheckedArray[byte], keySize: uint32, data: ptr UncheckedArray[byte], dataSize: uint32): array[br_sha512_SIZE, byte] =
  var hmacKeyCtx: br_hmac_key_context
  var hmacCtx: br_hmac_context
  br_hmac_key_init(addr hmacKeyCtx, addr br_sha512_vtable, cast[pointer](key), keySize.csize_t)
  br_hmac_init(addr hmacCtx, addr hmacKeyCtx, br_sha512_SIZE.csize_t)
  br_hmac_update(addr hmacCtx, cast[pointer](data), dataSize.csize_t)
  discard br_hmac_out(addr hmacCtx, addr result)

const
  br_sha1_SIZE = 20

var br_sha1_vtable {.importc.}: br_hash_class

proc sha1Hmac*(key: ptr UncheckedArray[byte], keySize: uint32, data: ptr UncheckedArray[byte], dataSize: uint32): array[br_sha1_SIZE, byte] =
  var hmacKeyCtx: br_hmac_key_context
  var hmacCtx: br_hmac_context
  br_hmac_key_init(addr hmacKeyCtx, addr br_sha1_vtable, cast[pointer](key), keySize.csize_t)
  br_hmac_init(addr hmacCtx, addr hmacKeyCtx, br_sha1_SIZE.csize_t)
  br_hmac_update(addr hmacCtx, cast[pointer](data), dataSize.csize_t)
  discard br_hmac_out(addr hmacCtx, addr result)
