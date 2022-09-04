##
##  Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
##
##  Permission is hereby granted, free of charge, to any person obtaining
##  a copy of this software and associated documentation files (the
##  "Software"), to deal in the Software without restriction, including
##  without limitation the rights to use, copy, modify, merge, publish,
##  distribute, sublicense, and/or sell copies of the Software, and to
##  permit persons to whom the Software is furnished to do so, subject to
##  the following conditions:
##
##  The above copyright notice and this permission notice shall be
##  included in all copies or substantial portions of the Software.
##
##  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
##  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
##  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
##  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
##  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
##  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
##  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
##  SOFTWARE.
##

type
  uint32_t = uint32
  uint64_t = uint64

## * \file bearssl_block.h
##
##  # Block Ciphers and Symmetric Ciphers
##
##  This file documents the API for block ciphers and other symmetric
##  ciphers.
##
##
##  ## Procedural API
##
##  For a block cipher implementation, up to three separate sets of
##  functions are provided, for CBC encryption, CBC decryption, and CTR
##  encryption/decryption. Each set has its own context structure,
##  initialised with the encryption key.
##
##  For CBC encryption and decryption, the data to encrypt or decrypt is
##  referenced as a sequence of blocks. The implementations assume that
##  there is no partial block; no padding is applied or removed. The
##  caller is responsible for handling any kind of padding.
##
##  Function for CTR encryption are defined only for block ciphers with
##  blocks of 16 bytes or more (i.e. AES, but not DES/3DES).
##
##  Each implemented block cipher is identified by an "internal name"
##  from which are derived the names of structures and functions that
##  implement the cipher. For the block cipher of internal name "`xxx`",
##  the following are defined:
##
##    - `br_xxx_BLOCK_SIZE`
##
##      A macro that evaluates to the block size (in bytes) of the
##      cipher. For all implemented block ciphers, this value is a
##      power of two.
##
##    - `br_xxx_cbcenc_keys`
##
##      Context structure that contains the subkeys resulting from the key
##      expansion. These subkeys are appropriate for CBC encryption. The
##      structure first field is called `vtable` and points to the
##      appropriate OOP structure.
##
##    - `br_xxx_cbcenc_init(br_xxx_cbcenc_keys *ctx, const void *key, size_t len)`
##
##      Perform key expansion: subkeys for CBC encryption are computed and
##      written in the provided context structure. The key length MUST be
##      adequate for the implemented block cipher. This function also sets
##      the `vtable` field.
##
##    - `br_xxx_cbcenc_run(const br_xxx_cbcenc_keys *ctx, void *iv, void *data, size_t len)`
##
##      Perform CBC encryption of `len` bytes, in place. The encrypted data
##      replaces the cleartext. `len` MUST be a multiple of the block length
##      (if it is not, the function may loop forever or overflow a buffer).
##      The IV is provided with the `iv` pointer; it is also updated with
##      a copy of the last encrypted block.
##
##    - `br_xxx_cbcdec_keys`
##
##      Context structure that contains the subkeys resulting from the key
##      expansion. These subkeys are appropriate for CBC decryption. The
##      structure first field is called `vtable` and points to the
##      appropriate OOP structure.
##
##    - `br_xxx_cbcdec_init(br_xxx_cbcenc_keys *ctx, const void *key, size_t len)`
##
##      Perform key expansion: subkeys for CBC decryption are computed and
##      written in the provided context structure. The key length MUST be
##      adequate for the implemented block cipher. This function also sets
##      the `vtable` field.
##
##    - `br_xxx_cbcdec_run(const br_xxx_cbcdec_keys *ctx, void *iv, void *data, size_t num_blocks)`
##
##      Perform CBC decryption of `len` bytes, in place. The decrypted data
##      replaces the ciphertext. `len` MUST be a multiple of the block length
##      (if it is not, the function may loop forever or overflow a buffer).
##      The IV is provided with the `iv` pointer; it is also updated with
##      a copy of the last _encrypted_ block.
##
##    - `br_xxx_ctr_keys`
##
##      Context structure that contains the subkeys resulting from the key
##      expansion. These subkeys are appropriate for CTR encryption and
##      decryption. The structure first field is called `vtable` and
##      points to the appropriate OOP structure.
##
##    - `br_xxx_ctr_init(br_xxx_ctr_keys *ctx, const void *key, size_t len)`
##
##      Perform key expansion: subkeys for CTR encryption and decryption
##      are computed and written in the provided context structure. The
##      key length MUST be adequate for the implemented block cipher. This
##      function also sets the `vtable` field.
##
##    - `br_xxx_ctr_run(const br_xxx_ctr_keys *ctx, const void *iv, uint32_t cc, void *data, size_t len)` (returns `uint32_t`)
##
##      Perform CTR encryption/decryption of some data. Processing is done
##      "in place" (the output data replaces the input data). This function
##      implements the "standard incrementing function" from NIST SP800-38A,
##      annex B: the IV length shall be 4 bytes less than the block size
##      (i.e. 12 bytes for AES) and the counter is the 32-bit value starting
##      with `cc`. The data length (`len`) is not necessarily a multiple of
##      the block size. The new counter value is returned, which supports
##      chunked processing, provided that each chunk length (except possibly
##      the last one) is a multiple of the block size.
##
##    - `br_xxx_ctrcbc_keys`
##
##      Context structure that contains the subkeys resulting from the
##      key expansion. These subkeys are appropriate for doing combined
##      CTR encryption/decryption and CBC-MAC, as used in the CCM and EAX
##      authenticated encryption modes. The structure first field is
##      called `vtable` and points to the appropriate OOP structure.
##
##    - `br_xxx_ctrcbc_init(br_xxx_ctr_keys *ctx, const void *key, size_t len)`
##
##      Perform key expansion: subkeys for combined CTR
##      encryption/decryption and CBC-MAC are computed and written in the
##      provided context structure. The key length MUST be adequate for
##      the implemented block cipher. This function also sets the
##      `vtable` field.
##
##    - `br_xxx_ctrcbc_encrypt(const br_xxx_ctrcbc_keys *ctx, void *ctr, void *cbcmac, void *data, size_t len)`
##
##      Perform CTR encryption of some data, and CBC-MAC. Processing is
##      done "in place" (the output data replaces the input data). This
##      function applies CTR encryption on the data, using a full
##      block-size counter (i.e. for 128-bit blocks, the counter is
##      incremented as a 128-bit value). The 'ctr' array contains the
##      initial value for the counter (used in the first block) and it is
##      updated with the new value after data processing. The 'cbcmac'
##      value shall point to a block-sized value which is used as IV for
##      CBC-MAC, computed over the encrypted data (output of CTR
##      encryption); the resulting CBC-MAC is written over 'cbcmac' on
##      output.
##
##      The data length MUST be a multiple of the block size.
##
##    - `br_xxx_ctrcbc_decrypt(const br_xxx_ctrcbc_keys *ctx, void *ctr, void *cbcmac, void *data, size_t len)`
##
##      Perform CTR decryption of some data, and CBC-MAC. Processing is
##      done "in place" (the output data replaces the input data). This
##      function applies CTR decryption on the data, using a full
##      block-size counter (i.e. for 128-bit blocks, the counter is
##      incremented as a 128-bit value). The 'ctr' array contains the
##      initial value for the counter (used in the first block) and it is
##      updated with the new value after data processing. The 'cbcmac'
##      value shall point to a block-sized value which is used as IV for
##      CBC-MAC, computed over the encrypted data (input of CTR
##      encryption); the resulting CBC-MAC is written over 'cbcmac' on
##      output.
##
##      The data length MUST be a multiple of the block size.
##
##    - `br_xxx_ctrcbc_ctr(const br_xxx_ctrcbc_keys *ctx, void *ctr, void *data, size_t len)`
##
##      Perform CTR encryption or decryption of the provided data. The
##      data is processed "in place" (the output data replaces the input
##      data). A full block-sized counter is applied (i.e. for 128-bit
##      blocks, the counter is incremented as a 128-bit value). The 'ctr'
##      array contains the initial value for the counter (used in the
##      first block), and it is updated with the new value after data
##      processing.
##
##      The data length MUST be a multiple of the block size.
##
##    - `br_xxx_ctrcbc_mac(const br_xxx_ctrcbc_keys *ctx, void *cbcmac, const void *data, size_t len)`
##
##      Compute CBC-MAC over the provided data. The IV for CBC-MAC is
##      provided as 'cbcmac'; the output is written over the same array.
##      The data itself is untouched. The data length MUST be a multiple
##      of the block size.
##
##
##  It shall be noted that the key expansion functions return `void`. If
##  the provided key length is not allowed, then there will be no error
##  reporting; implementations need not validate the key length, thus an
##  invalid key length may result in undefined behaviour (e.g. buffer
##  overflow).
##
##  Subkey structures contain no interior pointer, and no external
##  resources are allocated upon key expansion. They can thus be
##  discarded without any explicit deallocation.
##
##
##  ## Object-Oriented API
##
##  Each context structure begins with a field (called `vtable`) that
##  points to an instance of a structure that references the relevant
##  functions through pointers. Each such structure contains the
##  following:
##
##    - `context_size`
##
##      The size (in bytes) of the context structure for subkeys.
##
##    - `block_size`
##
##      The cipher block size (in bytes).
##
##    - `log_block_size`
##
##      The base-2 logarithm of cipher block size (e.g. 4 for blocks
##      of 16 bytes).
##
##    - `init`
##
##      Pointer to the key expansion function.
##
##    - `run`
##
##      Pointer to the encryption/decryption function.
##
##  For combined CTR/CBC-MAC encryption, the `vtable` has a slightly
##  different structure:
##
##    - `context_size`
##
##      The size (in bytes) of the context structure for subkeys.
##
##    - `block_size`
##
##      The cipher block size (in bytes).
##
##    - `log_block_size`
##
##      The base-2 logarithm of cipher block size (e.g. 4 for blocks
##      of 16 bytes).
##
##    - `init`
##
##      Pointer to the key expansion function.
##
##    - `encrypt`
##
##      Pointer to the CTR encryption + CBC-MAC function.
##
##    - `decrypt`
##
##      Pointer to the CTR decryption + CBC-MAC function.
##
##    - `ctr`
##
##      Pointer to the CTR encryption/decryption function.
##
##    - `mac`
##
##      Pointer to the CBC-MAC function.
##
##  For block cipher "`xxx`", static, constant instances of these
##  structures are defined, under the names:
##
##    - `br_xxx_cbcenc_vtable`
##    - `br_xxx_cbcdec_vtable`
##    - `br_xxx_ctr_vtable`
##    - `br_xxx_ctrcbc_vtable`
##
##
##  ## Implemented Block Ciphers
##
##  Provided implementations are:
##
##  | Name      | Function | Block Size (bytes) | Key lengths (bytes) |
##  | :-------- | :------- | :----------------: | :-----------------: |
##  | aes_big   | AES      |        16          | 16, 24 and 32       |
##  | aes_small | AES      |        16          | 16, 24 and 32       |
##  | aes_ct    | AES      |        16          | 16, 24 and 32       |
##  | aes_ct64  | AES      |        16          | 16, 24 and 32       |
##  | aes_x86ni | AES      |        16          | 16, 24 and 32       |
##  | aes_pwr8  | AES      |        16          | 16, 24 and 32       |
##  | des_ct    | DES/3DES |         8          | 8, 16 and 24        |
##  | des_tab   | DES/3DES |         8          | 8, 16 and 24        |
##
##  **Note:** DES/3DES nominally uses keys of 64, 128 and 192 bits (i.e. 8,
##  16 and 24 bytes), but some of the bits are ignored by the algorithm, so
##  the _effective_ key lengths, from a security point of view, are 56,
##  112 and 168 bits, respectively.
##
##  `aes_big` is a "classical" AES implementation, using tables. It
##  is fast but not constant-time, since it makes data-dependent array
##  accesses.
##
##  `aes_small` is an AES implementation optimized for code size. It
##  is substantially slower than `aes_big`; it is not constant-time
##  either.
##
##  `aes_ct` is a constant-time implementation of AES; its code is about
##  as big as that of `aes_big`, while its performance is comparable to
##  that of `aes_small`. However, it is constant-time. This
##  implementation should thus be considered to be the "default" AES in
##  BearSSL, to be used unless the operational context guarantees that a
##  non-constant-time implementation is safe, or an architecture-specific
##  constant-time implementation can be used (e.g. using dedicated
##  hardware opcodes).
##
##  `aes_ct64` is another constant-time implementation of AES. It is
##  similar to `aes_ct` but uses 64-bit values. On 32-bit machines,
##  `aes_ct64` is not faster than `aes_ct`, often a bit slower, and has
##  a larger footprint; however, on 64-bit architectures, `aes_ct64`
##  is typically twice faster than `aes_ct` for modes that allow parallel
##  operations (i.e. CTR, and CBC decryption, but not CBC encryption).
##
##  `aes_x86ni` exists only on x86 architectures (32-bit and 64-bit). It
##  uses the AES-NI opcodes when available.
##
##  `aes_pwr8` exists only on PowerPC / POWER architectures (32-bit and
##  64-bit, both little-endian and big-endian). It uses the AES opcodes
##  present in POWER8 and later.
##
##  `des_tab` is a classic, table-based implementation of DES/3DES. It
##  is not constant-time.
##
##  `des_ct` is an constant-time implementation of DES/3DES. It is
##  substantially slower than `des_tab`.
##
##  ## ChaCha20 and Poly1305
##
##  ChaCha20 is a stream cipher. Poly1305 is a MAC algorithm. They
##  are described in [RFC 7539](https://tools.ietf.org/html/rfc7539).
##
##  Two function pointer types are defined:
##
##    - `br_chacha20_run` describes a function that implements ChaCha20
##      only.
##
##    - `br_poly1305_run` describes an implementation of Poly1305,
##      in the AEAD combination with ChaCha20 specified in RFC 7539
##      (the ChaCha20 implementation is provided as a function pointer).
##
##  `chacha20_ct` is a straightforward implementation of ChaCha20 in
##  plain C; it is constant-time, small, and reasonably fast.
##
##  `chacha20_sse2` leverages SSE2 opcodes (on x86 architectures that
##  support these opcodes). It is faster than `chacha20_ct`.
##
##  `poly1305_ctmul` is an implementation of the ChaCha20+Poly1305 AEAD
##  construction, where the Poly1305 part is performed with mixed 32-bit
##  multiplications (operands are 32-bit, result is 64-bit).
##
##  `poly1305_ctmul32` implements ChaCha20+Poly1305 using pure 32-bit
##  multiplications (32-bit operands, 32-bit result). It is slower than
##  `poly1305_ctmul`, except on some specific architectures such as
##  the ARM Cortex M0+.
##
##  `poly1305_ctmulq` implements ChaCha20+Poly1305 with mixed 64-bit
##  multiplications (operands are 64-bit, result is 128-bit) on 64-bit
##  platforms that support such operations.
##
##  `poly1305_i15` implements ChaCha20+Poly1305 with the generic "i15"
##  big integer implementation. It is meant mostly for testing purposes,
##  although it can help with saving a few hundred bytes of code footprint
##  on systems where code size is scarce.
##
## *
##  \brief Class type for CBC encryption implementations.
##
##  A `br_block_cbcenc_class` instance points to the functions implementing
##  a specific block cipher, when used in CBC mode for encrypting data.
##

type
  br_block_cbcenc_class* = br_block_cbcenc_class_0
  br_block_cbcenc_class_0* {.bycopy.} = object
    context_size*: csize_t ## *
                         ##  \brief Size (in bytes) of the context structure appropriate
                         ##  for containing subkeys.
                         ##
    ## *
    ##  \brief Size of individual blocks (in bytes).
    ##
    block_size*: cuint ## *
                     ##  \brief Base-2 logarithm of the size of individual blocks,
                     ##  expressed in bytes.
                     ##
    log_block_size*: cuint ## *
                         ##  \brief Initialisation function.
                         ##
                         ##  This function sets the `vtable` field in the context structure.
                         ##  The key length MUST be one of the key lengths supported by
                         ##  the implementation.
                         ##
                         ##  \param ctx       context structure to initialise.
                         ##  \param key       secret key.
                         ##  \param key_len   key length (in bytes).
                         ##
    init*: proc (ctx: ptr ptr br_block_cbcenc_class; key: pointer; key_len: csize_t) ## *
                                                                           ##  \brief Run the CBC encryption.
                                                                           ##
                                                                           ##  The `iv` parameter points to the IV for this run; it is
                                                                           ##  updated with a copy of the last encrypted block. The data
                                                                           ##  is encrypted "in place"; its length (`len`) MUST be a
                                                                           ##  multiple of the block size.
                                                                           ##
                                                                           ##  \param ctx    context structure (already initialised).
                                                                           ##  \param iv     IV for CBC encryption (updated).
                                                                           ##  \param data   data to encrypt.
                                                                           ##  \param len    data length (in bytes, multiple of block size).
                                                                           ##
    run*: proc (ctx: ptr ptr br_block_cbcenc_class; iv: pointer; data: pointer;
              len: csize_t)


## *
##  \brief Class type for CBC decryption implementations.
##
##  A `br_block_cbcdec_class` instance points to the functions implementing
##  a specific block cipher, when used in CBC mode for decrypting data.
##

type
  br_block_cbcdec_class* = br_block_cbcdec_class_0
  br_block_cbcdec_class_0* {.bycopy.} = object
    context_size*: csize_t ## *
                         ##  \brief Size (in bytes) of the context structure appropriate
                         ##  for containing subkeys.
                         ##
    ## *
    ##  \brief Size of individual blocks (in bytes).
    ##
    block_size*: cuint ## *
                     ##  \brief Base-2 logarithm of the size of individual blocks,
                     ##  expressed in bytes.
                     ##
    log_block_size*: cuint ## *
                         ##  \brief Initialisation function.
                         ##
                         ##  This function sets the `vtable` field in the context structure.
                         ##  The key length MUST be one of the key lengths supported by
                         ##  the implementation.
                         ##
                         ##  \param ctx       context structure to initialise.
                         ##  \param key       secret key.
                         ##  \param key_len   key length (in bytes).
                         ##
    init*: proc (ctx: ptr ptr br_block_cbcdec_class; key: pointer; key_len: csize_t) ## *
                                                                           ##  \brief Run the CBC decryption.
                                                                           ##
                                                                           ##  The `iv` parameter points to the IV for this run; it is
                                                                           ##  updated with a copy of the last encrypted block. The data
                                                                           ##  is decrypted "in place"; its length (`len`) MUST be a
                                                                           ##  multiple of the block size.
                                                                           ##
                                                                           ##  \param ctx    context structure (already initialised).
                                                                           ##  \param iv     IV for CBC decryption (updated).
                                                                           ##  \param data   data to decrypt.
                                                                           ##  \param len    data length (in bytes, multiple of block size).
                                                                           ##
    run*: proc (ctx: ptr ptr br_block_cbcdec_class; iv: pointer; data: pointer;
              len: csize_t)


## *
##  \brief Class type for CTR encryption/decryption implementations.
##
##  A `br_block_ctr_class` instance points to the functions implementing
##  a specific block cipher, when used in CTR mode for encrypting or
##  decrypting data.
##

type
  br_block_ctr_class* = br_block_ctr_class_0
  br_block_ctr_class_0* {.bycopy.} = object
    context_size*: csize_t ## *
                         ##  \brief Size (in bytes) of the context structure appropriate
                         ##  for containing subkeys.
                         ##
    ## *
    ##  \brief Size of individual blocks (in bytes).
    ##
    block_size*: cuint ## *
                     ##  \brief Base-2 logarithm of the size of individual blocks,
                     ##  expressed in bytes.
                     ##
    log_block_size*: cuint ## *
                         ##  \brief Initialisation function.
                         ##
                         ##  This function sets the `vtable` field in the context structure.
                         ##  The key length MUST be one of the key lengths supported by
                         ##  the implementation.
                         ##
                         ##  \param ctx       context structure to initialise.
                         ##  \param key       secret key.
                         ##  \param key_len   key length (in bytes).
                         ##
    init*: proc (ctx: ptr ptr br_block_ctr_class; key: pointer; key_len: csize_t) ## *
                                                                        ##  \brief Run the CTR encryption or decryption.
                                                                        ##
                                                                        ##  The `iv` parameter points to the IV for this run; its
                                                                        ##  length is exactly 4 bytes less than the block size (e.g.
                                                                        ##  12 bytes for AES/CTR). The IV is combined with a 32-bit
                                                                        ##  block counter to produce the block value which is processed
                                                                        ##  with the block cipher.
                                                                        ##
                                                                        ##  The data to encrypt or decrypt is updated "in place". Its
                                                                        ##  length (`len` bytes) is not required to be a multiple of
                                                                        ##  the block size; if the final block is partial, then the
                                                                        ##  corresponding key stream bits are dropped.
                                                                        ##
                                                                        ##  The resulting counter value is returned.
                                                                        ##
                                                                        ##  \param ctx    context structure (already initialised).
                                                                        ##  \param iv     IV for CTR encryption/decryption.
                                                                        ##  \param cc     initial value for the block counter.
                                                                        ##  \param data   data to encrypt or decrypt.
                                                                        ##  \param len    data length (in bytes).
                                                                        ##  \return  the new block counter value.
                                                                        ##
    run*: proc (ctx: ptr ptr br_block_ctr_class; iv: pointer; cc: uint32_t; data: pointer;
              len: csize_t): uint32_t


## *
##  \brief Class type for combined CTR and CBC-MAC implementations.
##
##  A `br_block_ctrcbc_class` instance points to the functions implementing
##  a specific block cipher, when used in CTR mode for encrypting or
##  decrypting data, along with CBC-MAC.
##

type
  br_block_ctrcbc_class* = br_block_ctrcbc_class_0
  br_block_ctrcbc_class_0* {.bycopy.} = object
    context_size*: csize_t ## *
                         ##  \brief Size (in bytes) of the context structure appropriate
                         ##  for containing subkeys.
                         ##
    ## *
    ##  \brief Size of individual blocks (in bytes).
    ##
    block_size*: cuint ## *
                     ##  \brief Base-2 logarithm of the size of individual blocks,
                     ##  expressed in bytes.
                     ##
    log_block_size*: cuint ## *
                         ##  \brief Initialisation function.
                         ##
                         ##  This function sets the `vtable` field in the context structure.
                         ##  The key length MUST be one of the key lengths supported by
                         ##  the implementation.
                         ##
                         ##  \param ctx       context structure to initialise.
                         ##  \param key       secret key.
                         ##  \param key_len   key length (in bytes).
                         ##
    init*: proc (ctx: ptr ptr br_block_ctrcbc_class; key: pointer; key_len: csize_t) ## *
                                                                           ##  \brief Run the CTR encryption + CBC-MAC.
                                                                           ##
                                                                           ##  The `ctr` parameter points to the counter; its length shall
                                                                           ##  be equal to the block size. It is updated by this function
                                                                           ##  as encryption proceeds.
                                                                           ##
                                                                           ##  The `cbcmac` parameter points to the IV for CBC-MAC. The MAC
                                                                           ##  is computed over the encrypted data (output of CTR
                                                                           ##  encryption). Its length shall be equal to the block size. The
                                                                           ##  computed CBC-MAC value is written over the `cbcmac` array.
                                                                           ##
                                                                           ##  The data to encrypt is updated "in place". Its length (`len`
                                                                           ##  bytes) MUST be a multiple of the block size.
                                                                           ##
                                                                           ##  \param ctx      context structure (already initialised).
                                                                           ##  \param ctr      counter for CTR encryption (initial and final).
                                                                           ##  \param cbcmac   IV and output buffer for CBC-MAC.
                                                                           ##  \param data     data to encrypt.
                                                                           ##  \param len      data length (in bytes).
                                                                           ##
    encrypt*: proc (ctx: ptr ptr br_block_ctrcbc_class; ctr: pointer; cbcmac: pointer;
                  data: pointer; len: csize_t) ## *
                                           ##  \brief Run the CTR decryption + CBC-MAC.
                                           ##
                                           ##  The `ctr` parameter points to the counter; its length shall
                                           ##  be equal to the block size. It is updated by this function
                                           ##  as decryption proceeds.
                                           ##
                                           ##  The `cbcmac` parameter points to the IV for CBC-MAC. The MAC
                                           ##  is computed over the encrypted data (i.e. before CTR
                                           ##  decryption). Its length shall be equal to the block size. The
                                           ##  computed CBC-MAC value is written over the `cbcmac` array.
                                           ##
                                           ##  The data to decrypt is updated "in place". Its length (`len`
                                           ##  bytes) MUST be a multiple of the block size.
                                           ##
                                           ##  \param ctx      context structure (already initialised).
                                           ##  \param ctr      counter for CTR encryption (initial and final).
                                           ##  \param cbcmac   IV and output buffer for CBC-MAC.
                                           ##  \param data     data to decrypt.
                                           ##  \param len      data length (in bytes).
                                           ##
    decrypt*: proc (ctx: ptr ptr br_block_ctrcbc_class; ctr: pointer; cbcmac: pointer;
                  data: pointer; len: csize_t) ## *
                                           ##  \brief Run the CTR encryption/decryption only.
                                           ##
                                           ##  The `ctr` parameter points to the counter; its length shall
                                           ##  be equal to the block size. It is updated by this function
                                           ##  as decryption proceeds.
                                           ##
                                           ##  The data to decrypt is updated "in place". Its length (`len`
                                           ##  bytes) MUST be a multiple of the block size.
                                           ##
                                           ##  \param ctx      context structure (already initialised).
                                           ##  \param ctr      counter for CTR encryption (initial and final).
                                           ##  \param data     data to decrypt.
                                           ##  \param len      data length (in bytes).
                                           ##
    ctr*: proc (ctx: ptr ptr br_block_ctrcbc_class; ctr: pointer; data: pointer;
              len: csize_t) ## *
                          ##  \brief Run the CBC-MAC only.
                          ##
                          ##  The `cbcmac` parameter points to the IV for CBC-MAC. The MAC
                          ##  is computed over the encrypted data (i.e. before CTR
                          ##  decryption). Its length shall be equal to the block size. The
                          ##  computed CBC-MAC value is written over the `cbcmac` array.
                          ##
                          ##  The data is unmodified. Its length (`len` bytes) MUST be a
                          ##  multiple of the block size.
                          ##
                          ##  \param ctx      context structure (already initialised).
                          ##  \param cbcmac   IV and output buffer for CBC-MAC.
                          ##  \param data     data to decrypt.
                          ##  \param len      data length (in bytes).
                          ##
    mac*: proc (ctx: ptr ptr br_block_ctrcbc_class; cbcmac: pointer; data: pointer;
              len: csize_t)


##
##  Traditional, table-based AES implementation. It is fast, but uses
##  internal tables (in particular a 1 kB table for encryption, another
##  1 kB table for decryption, and a 256-byte table for key schedule),
##  and it is not constant-time. In contexts where cache-timing attacks
##  apply, this implementation may leak the secret key.
##
## * \brief AES block size (16 bytes).

const
  br_aes_big_BLOCK_SIZE* = 16

## *
##  \brief Context for AES subkeys (`aes_big` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_big_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_big` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_big_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_big` implementation, CTR encryption
##  and decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_big_ctr_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctr_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_big` implementation, CTR encryption
##  and decryption + CBC-MAC).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_big_ctrcbc_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctrcbc_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Class instance for AES CBC encryption (`aes_big` implementation).
##

let br_aes_big_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for AES CBC decryption (`aes_big` implementation).
##

let br_aes_big_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Class instance for AES CTR encryption and decryption
##  (`aes_big` implementation).
##

let br_aes_big_ctr_vtable* {.importc, nodecl.}: br_block_ctr_class

## *
##  \brief Class instance for AES CTR encryption/decryption + CBC-MAC
##  (`aes_big` implementation).
##

let br_aes_big_ctrcbc_vtable* {.importc, nodecl.}: br_block_ctrcbc_class

## *
##  \brief Context initialisation (key schedule) for AES CBC encryption
##  (`aes_big` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_big_cbcenc_init*(ctx: ptr br_aes_big_cbcenc_keys; key: pointer;
                            len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CBC decryption
##  (`aes_big` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_big_cbcdec_init*(ctx: ptr br_aes_big_cbcdec_keys; key: pointer;
                            len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR encryption
##  and decryption (`aes_big` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_big_ctr_init*(ctx: ptr br_aes_big_ctr_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR + CBC-MAC
##  (`aes_big` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_big_ctrcbc_init*(ctx: ptr br_aes_big_ctrcbc_keys; key: pointer;
                            len: csize_t) {.importc.}
## *
##  \brief CBC encryption with AES (`aes_big` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_big_cbcenc_run*(ctx: ptr br_aes_big_cbcenc_keys; iv: pointer;
                           data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC decryption with AES (`aes_big` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_big_cbcdec_run*(ctx: ptr br_aes_big_cbcdec_keys; iv: pointer;
                           data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption and decryption with AES (`aes_big` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (constant, 12 bytes).
##  \param cc     initial block counter value.
##  \param data   data to encrypt or decrypt (updated).
##  \param len    data length (in bytes).
##  \return  new block counter value.
##

proc br_aes_big_ctr_run*(ctx: ptr br_aes_big_ctr_keys; iv: pointer; cc: uint32_t;
                        data: pointer; len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief CTR encryption + CBC-MAC with AES (`aes_big` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to encrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_big_ctrcbc_encrypt*(ctx: ptr br_aes_big_ctrcbc_keys; ctr: pointer;
                               cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR decryption + CBC-MAC with AES (`aes_big` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to decrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_big_ctrcbc_decrypt*(ctx: ptr br_aes_big_ctrcbc_keys; ctr: pointer;
                               cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption/decryption with AES (`aes_big` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param data     data to MAC (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_big_ctrcbc_ctr*(ctx: ptr br_aes_big_ctrcbc_keys; ctr: pointer;
                           data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC-MAC with AES (`aes_big` implementation).
##
##  \param ctx      context (already initialised).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to MAC (unmodified).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_big_ctrcbc_mac*(ctx: ptr br_aes_big_ctrcbc_keys; cbcmac: pointer;
                           data: pointer; len: csize_t) {.importc.}
##
##  AES implementation optimized for size. It is slower than the
##  traditional table-based AES implementation, but requires much less
##  code. It still uses data-dependent table accesses (albeit within a
##  much smaller 256-byte table), which makes it conceptually vulnerable
##  to cache-timing attacks.
##
## * \brief AES block size (16 bytes).

const
  br_aes_small_BLOCK_SIZE* = 16

## *
##  \brief Context for AES subkeys (`aes_small` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_small_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_small` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_small_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_small` implementation, CTR encryption
##  and decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_small_ctr_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctr_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_small` implementation, CTR encryption
##  and decryption + CBC-MAC).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_small_ctrcbc_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctrcbc_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Class instance for AES CBC encryption (`aes_small` implementation).
##

let br_aes_small_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for AES CBC decryption (`aes_small` implementation).
##

let br_aes_small_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Class instance for AES CTR encryption and decryption
##  (`aes_small` implementation).
##

let br_aes_small_ctr_vtable* {.importc, nodecl.}: br_block_ctr_class

## *
##  \brief Class instance for AES CTR encryption/decryption + CBC-MAC
##  (`aes_small` implementation).
##

let br_aes_small_ctrcbc_vtable* {.importc, nodecl.}: br_block_ctrcbc_class

## *
##  \brief Context initialisation (key schedule) for AES CBC encryption
##  (`aes_small` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_small_cbcenc_init*(ctx: ptr br_aes_small_cbcenc_keys; key: pointer;
                              len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CBC decryption
##  (`aes_small` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_small_cbcdec_init*(ctx: ptr br_aes_small_cbcdec_keys; key: pointer;
                              len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR encryption
##  and decryption (`aes_small` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_small_ctr_init*(ctx: ptr br_aes_small_ctr_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR + CBC-MAC
##  (`aes_small` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_small_ctrcbc_init*(ctx: ptr br_aes_small_ctrcbc_keys; key: pointer;
                              len: csize_t) {.importc.}
## *
##  \brief CBC encryption with AES (`aes_small` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_small_cbcenc_run*(ctx: ptr br_aes_small_cbcenc_keys; iv: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC decryption with AES (`aes_small` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_small_cbcdec_run*(ctx: ptr br_aes_small_cbcdec_keys; iv: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption and decryption with AES (`aes_small` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (constant, 12 bytes).
##  \param cc     initial block counter value.
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes).
##  \return  new block counter value.
##

proc br_aes_small_ctr_run*(ctx: ptr br_aes_small_ctr_keys; iv: pointer; cc: uint32_t;
                          data: pointer; len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief CTR encryption + CBC-MAC with AES (`aes_small` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to encrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_small_ctrcbc_encrypt*(ctx: ptr br_aes_small_ctrcbc_keys; ctr: pointer;
                                 cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR decryption + CBC-MAC with AES (`aes_small` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to decrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_small_ctrcbc_decrypt*(ctx: ptr br_aes_small_ctrcbc_keys; ctr: pointer;
                                 cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption/decryption with AES (`aes_small` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param data     data to MAC (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_small_ctrcbc_ctr*(ctx: ptr br_aes_small_ctrcbc_keys; ctr: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC-MAC with AES (`aes_small` implementation).
##
##  \param ctx      context (already initialised).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to MAC (unmodified).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_small_ctrcbc_mac*(ctx: ptr br_aes_small_ctrcbc_keys; cbcmac: pointer;
                             data: pointer; len: csize_t) {.importc.}
##
##  Constant-time AES implementation. Its size is similar to that of
##  'aes_big', and its performance is similar to that of 'aes_small' (faster
##  decryption, slower encryption). However, it is constant-time, i.e.
##  immune to cache-timing and similar attacks.
##
## * \brief AES block size (16 bytes).

const
  br_aes_ct_BLOCK_SIZE* = 16

## *
##  \brief Context for AES subkeys (`aes_ct` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_ct` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_ct` implementation, CTR encryption
##  and decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct_ctr_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctr_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_ct` implementation, CTR encryption
##  and decryption + CBC-MAC).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct_ctrcbc_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctrcbc_class ## * \brief Pointer to vtable for this context.
    skey*: array[60, uint32_t]
    num_rounds*: cuint


## *
##  \brief Class instance for AES CBC encryption (`aes_ct` implementation).
##

let br_aes_ct_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for AES CBC decryption (`aes_ct` implementation).
##

let br_aes_ct_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Class instance for AES CTR encryption and decryption
##  (`aes_ct` implementation).
##

let br_aes_ct_ctr_vtable* {.importc, nodecl.}: br_block_ctr_class

## *
##  \brief Class instance for AES CTR encryption/decryption + CBC-MAC
##  (`aes_ct` implementation).
##

let br_aes_ct_ctrcbc_vtable* {.importc, nodecl.}: br_block_ctrcbc_class

## *
##  \brief Context initialisation (key schedule) for AES CBC encryption
##  (`aes_ct` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct_cbcenc_init*(ctx: ptr br_aes_ct_cbcenc_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CBC decryption
##  (`aes_ct` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct_cbcdec_init*(ctx: ptr br_aes_ct_cbcdec_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR encryption
##  and decryption (`aes_ct` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct_ctr_init*(ctx: ptr br_aes_ct_ctr_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR + CBC-MAC
##  (`aes_ct` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct_ctrcbc_init*(ctx: ptr br_aes_ct_ctrcbc_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC encryption with AES (`aes_ct` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_ct_cbcenc_run*(ctx: ptr br_aes_ct_cbcenc_keys; iv: pointer; data: pointer;
                          len: csize_t) {.importc.}
## *
##  \brief CBC decryption with AES (`aes_ct` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_ct_cbcdec_run*(ctx: ptr br_aes_ct_cbcdec_keys; iv: pointer; data: pointer;
                          len: csize_t) {.importc.}
## *
##  \brief CTR encryption and decryption with AES (`aes_ct` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (constant, 12 bytes).
##  \param cc     initial block counter value.
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes).
##  \return  new block counter value.
##

proc br_aes_ct_ctr_run*(ctx: ptr br_aes_ct_ctr_keys; iv: pointer; cc: uint32_t;
                       data: pointer; len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief CTR encryption + CBC-MAC with AES (`aes_ct` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to encrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct_ctrcbc_encrypt*(ctx: ptr br_aes_ct_ctrcbc_keys; ctr: pointer;
                              cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR decryption + CBC-MAC with AES (`aes_ct` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to decrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct_ctrcbc_decrypt*(ctx: ptr br_aes_ct_ctrcbc_keys; ctr: pointer;
                              cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption/decryption with AES (`aes_ct` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param data     data to MAC (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct_ctrcbc_ctr*(ctx: ptr br_aes_ct_ctrcbc_keys; ctr: pointer;
                          data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC-MAC with AES (`aes_ct` implementation).
##
##  \param ctx      context (already initialised).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to MAC (unmodified).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct_ctrcbc_mac*(ctx: ptr br_aes_ct_ctrcbc_keys; cbcmac: pointer;
                          data: pointer; len: csize_t) {.importc.}
##
##  64-bit constant-time AES implementation. It is similar to 'aes_ct'
##  but uses 64-bit registers, making it about twice faster than 'aes_ct'
##  on 64-bit platforms, while remaining constant-time and with a similar
##  code size. (The doubling in performance is only for CBC decryption
##  and CTR mode; CBC encryption is non-parallel and cannot benefit from
##  the larger registers.)
##
## * \brief AES block size (16 bytes).

const
  br_aes_ct64_BLOCK_SIZE* = 16

## *
##  \brief Context for AES subkeys (`aes_ct64` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct64_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: array[30, uint64_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_ct64` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct64_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: array[30, uint64_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_ct64` implementation, CTR encryption
##  and decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct64_ctr_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctr_class ## * \brief Pointer to vtable for this context.
    skey*: array[30, uint64_t]
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_ct64` implementation, CTR encryption
##  and decryption + CBC-MAC).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_aes_ct64_ctrcbc_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctrcbc_class ## * \brief Pointer to vtable for this context.
    skey*: array[30, uint64_t]
    num_rounds*: cuint


## *
##  \brief Class instance for AES CBC encryption (`aes_ct64` implementation).
##

let br_aes_ct64_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for AES CBC decryption (`aes_ct64` implementation).
##

let br_aes_ct64_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Class instance for AES CTR encryption and decryption
##  (`aes_ct64` implementation).
##

let br_aes_ct64_ctr_vtable* {.importc, nodecl.}: br_block_ctr_class

## *
##  \brief Class instance for AES CTR encryption/decryption + CBC-MAC
##  (`aes_ct64` implementation).
##

let br_aes_ct64_ctrcbc_vtable* {.importc, nodecl.}: br_block_ctrcbc_class

## *
##  \brief Context initialisation (key schedule) for AES CBC encryption
##  (`aes_ct64` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct64_cbcenc_init*(ctx: ptr br_aes_ct64_cbcenc_keys; key: pointer;
                             len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CBC decryption
##  (`aes_ct64` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct64_cbcdec_init*(ctx: ptr br_aes_ct64_cbcdec_keys; key: pointer;
                             len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR encryption
##  and decryption (`aes_ct64` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct64_ctr_init*(ctx: ptr br_aes_ct64_ctr_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR + CBC-MAC
##  (`aes_ct64` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_ct64_ctrcbc_init*(ctx: ptr br_aes_ct64_ctrcbc_keys; key: pointer;
                             len: csize_t) {.importc.}
## *
##  \brief CBC encryption with AES (`aes_ct64` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_ct64_cbcenc_run*(ctx: ptr br_aes_ct64_cbcenc_keys; iv: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC decryption with AES (`aes_ct64` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_ct64_cbcdec_run*(ctx: ptr br_aes_ct64_cbcdec_keys; iv: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption and decryption with AES (`aes_ct64` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (constant, 12 bytes).
##  \param cc     initial block counter value.
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes).
##  \return  new block counter value.
##

proc br_aes_ct64_ctr_run*(ctx: ptr br_aes_ct64_ctr_keys; iv: pointer; cc: uint32_t;
                         data: pointer; len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief CTR encryption + CBC-MAC with AES (`aes_ct64` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to encrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct64_ctrcbc_encrypt*(ctx: ptr br_aes_ct64_ctrcbc_keys; ctr: pointer;
                                cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR decryption + CBC-MAC with AES (`aes_ct64` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to decrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct64_ctrcbc_decrypt*(ctx: ptr br_aes_ct64_ctrcbc_keys; ctr: pointer;
                                cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption/decryption with AES (`aes_ct64` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param data     data to MAC (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct64_ctrcbc_ctr*(ctx: ptr br_aes_ct64_ctrcbc_keys; ctr: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC-MAC with AES (`aes_ct64` implementation).
##
##  \param ctx      context (already initialised).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to MAC (unmodified).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_ct64_ctrcbc_mac*(ctx: ptr br_aes_ct64_ctrcbc_keys; cbcmac: pointer;
                            data: pointer; len: csize_t) {.importc.}
##
##  AES implementation using AES-NI opcodes (x86 platform).
##
## * \brief AES block size (16 bytes).

const
  br_aes_x86ni_BLOCK_SIZE* = 16

## *
##  \brief Context for AES subkeys (`aes_x86ni` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_1* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_x86ni_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_1
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_x86ni` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_3* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_x86ni_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_3
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_x86ni` implementation, CTR encryption
##  and decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_5* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_x86ni_ctr_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctr_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_5
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_x86ni` implementation, CTR encryption
##  and decryption + CBC-MAC).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_7* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_x86ni_ctrcbc_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctrcbc_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_7
    num_rounds*: cuint


## *
##  \brief Class instance for AES CBC encryption (`aes_x86ni` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_x86ni_cbcenc_get_vtable()`.
##

let br_aes_x86ni_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for AES CBC decryption (`aes_x86ni` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_x86ni_cbcdec_get_vtable()`.
##

let br_aes_x86ni_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Class instance for AES CTR encryption and decryption
##  (`aes_x86ni` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_x86ni_ctr_get_vtable()`.
##

let br_aes_x86ni_ctr_vtable* {.importc, nodecl.}: br_block_ctr_class

## *
##  \brief Class instance for AES CTR encryption/decryption + CBC-MAC
##  (`aes_x86ni` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_x86ni_ctrcbc_get_vtable()`.
##

let br_aes_x86ni_ctrcbc_vtable* {.importc, nodecl.}: br_block_ctrcbc_class

## *
##  \brief Context initialisation (key schedule) for AES CBC encryption
##  (`aes_x86ni` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_x86ni_cbcenc_init*(ctx: ptr br_aes_x86ni_cbcenc_keys; key: pointer;
                              len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CBC decryption
##  (`aes_x86ni` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_x86ni_cbcdec_init*(ctx: ptr br_aes_x86ni_cbcdec_keys; key: pointer;
                              len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR encryption
##  and decryption (`aes_x86ni` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_x86ni_ctr_init*(ctx: ptr br_aes_x86ni_ctr_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR + CBC-MAC
##  (`aes_x86ni` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_x86ni_ctrcbc_init*(ctx: ptr br_aes_x86ni_ctrcbc_keys; key: pointer;
                              len: csize_t) {.importc.}
## *
##  \brief CBC encryption with AES (`aes_x86ni` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_x86ni_cbcenc_run*(ctx: ptr br_aes_x86ni_cbcenc_keys; iv: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC decryption with AES (`aes_x86ni` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_x86ni_cbcdec_run*(ctx: ptr br_aes_x86ni_cbcdec_keys; iv: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption and decryption with AES (`aes_x86ni` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (constant, 12 bytes).
##  \param cc     initial block counter value.
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes).
##  \return  new block counter value.
##

proc br_aes_x86ni_ctr_run*(ctx: ptr br_aes_x86ni_ctr_keys; iv: pointer; cc: uint32_t;
                          data: pointer; len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief CTR encryption + CBC-MAC with AES (`aes_x86ni` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to encrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_x86ni_ctrcbc_encrypt*(ctx: ptr br_aes_x86ni_ctrcbc_keys; ctr: pointer;
                                 cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR decryption + CBC-MAC with AES (`aes_x86ni` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to decrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_x86ni_ctrcbc_decrypt*(ctx: ptr br_aes_x86ni_ctrcbc_keys; ctr: pointer;
                                 cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption/decryption with AES (`aes_x86ni` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param data     data to MAC (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_x86ni_ctrcbc_ctr*(ctx: ptr br_aes_x86ni_ctrcbc_keys; ctr: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC-MAC with AES (`aes_x86ni` implementation).
##
##  \param ctx      context (already initialised).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to MAC (unmodified).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_x86ni_ctrcbc_mac*(ctx: ptr br_aes_x86ni_ctrcbc_keys; cbcmac: pointer;
                             data: pointer; len: csize_t) {.importc.}
## *
##  \brief Obtain the `aes_x86ni` AES-CBC (encryption) implementation, if
##  available.
##
##  This function returns a pointer to `br_aes_x86ni_cbcenc_vtable`, if
##  that implementation was compiled in the library _and_ the x86 AES
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_x86ni` AES-CBC (encryption) implementation, or `NULL`.
##

proc br_aes_x86ni_cbcenc_get_vtable*(): ptr br_block_cbcenc_class {.importc.}
## *
##  \brief Obtain the `aes_x86ni` AES-CBC (decryption) implementation, if
##  available.
##
##  This function returns a pointer to `br_aes_x86ni_cbcdec_vtable`, if
##  that implementation was compiled in the library _and_ the x86 AES
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_x86ni` AES-CBC (decryption) implementation, or `NULL`.
##

proc br_aes_x86ni_cbcdec_get_vtable*(): ptr br_block_cbcdec_class {.importc.}
## *
##  \brief Obtain the `aes_x86ni` AES-CTR implementation, if available.
##
##  This function returns a pointer to `br_aes_x86ni_ctr_vtable`, if
##  that implementation was compiled in the library _and_ the x86 AES
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_x86ni` AES-CTR implementation, or `NULL`.
##

proc br_aes_x86ni_ctr_get_vtable*(): ptr br_block_ctr_class {.importc.}
## *
##  \brief Obtain the `aes_x86ni` AES-CTR + CBC-MAC implementation, if
##  available.
##
##  This function returns a pointer to `br_aes_x86ni_ctrcbc_vtable`, if
##  that implementation was compiled in the library _and_ the x86 AES
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_x86ni` AES-CTR implementation, or `NULL`.
##

proc br_aes_x86ni_ctrcbc_get_vtable*(): ptr br_block_ctrcbc_class {.importc.}
##
##  AES implementation using POWER8 opcodes.
##
## * \brief AES block size (16 bytes).

const
  br_aes_pwr8_BLOCK_SIZE* = 16

## *
##  \brief Context for AES subkeys (`aes_pwr8` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_9* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_pwr8_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_9
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_pwr8` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_11* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_pwr8_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_11
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_pwr8` implementation, CTR encryption
##  and decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_13* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_pwr8_ctr_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctr_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_13
    num_rounds*: cuint


## *
##  \brief Context for AES subkeys (`aes_pwr8` implementation, CTR encryption
##  and decryption + CBC-MAC).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  INNER_C_UNION_bearssl_block_15* {.bycopy, union.} = object
    skni*: array[16 * 15, uint8]

  br_aes_pwr8_ctrcbc_keys* {.bycopy.} = object
    vtable*: ptr br_block_ctrcbc_class ## * \brief Pointer to vtable for this context.
    skey*: INNER_C_UNION_bearssl_block_15
    num_rounds*: cuint


## *
##  \brief Class instance for AES CBC encryption (`aes_pwr8` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_pwr8_cbcenc_get_vtable()`.
##

let br_aes_pwr8_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for AES CBC decryption (`aes_pwr8` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_pwr8_cbcdec_get_vtable()`.
##

let br_aes_pwr8_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Class instance for AES CTR encryption and decryption
##  (`aes_pwr8` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_pwr8_ctr_get_vtable()`.
##

let br_aes_pwr8_ctr_vtable* {.importc, nodecl.}: br_block_ctr_class

## *
##  \brief Class instance for AES CTR encryption/decryption + CBC-MAC
##  (`aes_pwr8` implementation).
##
##  Since this implementation might be omitted from the library, or the
##  AES opcode unavailable on the current CPU, a pointer to this class
##  instance should be obtained through `br_aes_pwr8_ctrcbc_get_vtable()`.
##

let br_aes_pwr8_ctrcbc_vtable* {.importc, nodecl.}: br_block_ctrcbc_class

## *
##  \brief Context initialisation (key schedule) for AES CBC encryption
##  (`aes_pwr8` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_pwr8_cbcenc_init*(ctx: ptr br_aes_pwr8_cbcenc_keys; key: pointer;
                             len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CBC decryption
##  (`aes_pwr8` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_pwr8_cbcdec_init*(ctx: ptr br_aes_pwr8_cbcdec_keys; key: pointer;
                             len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR encryption
##  and decryption (`aes_pwr8` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_pwr8_ctr_init*(ctx: ptr br_aes_pwr8_ctr_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for AES CTR + CBC-MAC
##  (`aes_pwr8` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_aes_pwr8_ctrcbc_init*(ctx: ptr br_aes_pwr8_ctrcbc_keys; key: pointer;
                             len: csize_t) {.importc.}
## *
##  \brief CBC encryption with AES (`aes_pwr8` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_pwr8_cbcenc_run*(ctx: ptr br_aes_pwr8_cbcenc_keys; iv: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC decryption with AES (`aes_pwr8` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 16).
##

proc br_aes_pwr8_cbcdec_run*(ctx: ptr br_aes_pwr8_cbcdec_keys; iv: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption and decryption with AES (`aes_pwr8` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (constant, 12 bytes).
##  \param cc     initial block counter value.
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes).
##  \return  new block counter value.
##

proc br_aes_pwr8_ctr_run*(ctx: ptr br_aes_pwr8_ctr_keys; iv: pointer; cc: uint32_t;
                         data: pointer; len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief CTR encryption + CBC-MAC with AES (`aes_pwr8` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to encrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_pwr8_ctrcbc_encrypt*(ctx: ptr br_aes_pwr8_ctrcbc_keys; ctr: pointer;
                                cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR decryption + CBC-MAC with AES (`aes_pwr8` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to decrypt (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_pwr8_ctrcbc_decrypt*(ctx: ptr br_aes_pwr8_ctrcbc_keys; ctr: pointer;
                                cbcmac: pointer; data: pointer; len: csize_t) {.importc.}
## *
##  \brief CTR encryption/decryption with AES (`aes_pwr8` implementation).
##
##  \param ctx      context (already initialised).
##  \param ctr      counter for CTR (16 bytes, updated).
##  \param data     data to MAC (updated).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_pwr8_ctrcbc_ctr*(ctx: ptr br_aes_pwr8_ctrcbc_keys; ctr: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC-MAC with AES (`aes_pwr8` implementation).
##
##  \param ctx      context (already initialised).
##  \param cbcmac   IV for CBC-MAC (updated).
##  \param data     data to MAC (unmodified).
##  \param len      data length (in bytes, MUST be a multiple of 16).
##

proc br_aes_pwr8_ctrcbc_mac*(ctx: ptr br_aes_pwr8_ctrcbc_keys; cbcmac: pointer;
                            data: pointer; len: csize_t) {.importc.}
## *
##  \brief Obtain the `aes_pwr8` AES-CBC (encryption) implementation, if
##  available.
##
##  This function returns a pointer to `br_aes_pwr8_cbcenc_vtable`, if
##  that implementation was compiled in the library _and_ the POWER8
##  crypto opcodes are available on the currently running CPU. If either
##  of these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_pwr8` AES-CBC (encryption) implementation, or `NULL`.
##

proc br_aes_pwr8_cbcenc_get_vtable*(): ptr br_block_cbcenc_class {.importc.}
## *
##  \brief Obtain the `aes_pwr8` AES-CBC (decryption) implementation, if
##  available.
##
##  This function returns a pointer to `br_aes_pwr8_cbcdec_vtable`, if
##  that implementation was compiled in the library _and_ the POWER8
##  crypto opcodes are available on the currently running CPU. If either
##  of these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_pwr8` AES-CBC (decryption) implementation, or `NULL`.
##

proc br_aes_pwr8_cbcdec_get_vtable*(): ptr br_block_cbcdec_class {.importc.}
## *
##  \brief Obtain the `aes_pwr8` AES-CTR implementation, if available.
##
##  This function returns a pointer to `br_aes_pwr8_ctr_vtable`, if that
##  implementation was compiled in the library _and_ the POWER8 crypto
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_pwr8` AES-CTR implementation, or `NULL`.
##

proc br_aes_pwr8_ctr_get_vtable*(): ptr br_block_ctr_class {.importc.}
## *
##  \brief Obtain the `aes_pwr8` AES-CTR + CBC-MAC implementation, if
##  available.
##
##  This function returns a pointer to `br_aes_pwr8_ctrcbc_vtable`, if
##  that implementation was compiled in the library _and_ the POWER8 AES
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `NULL`.
##
##  \return  the `aes_pwr8` AES-CTR implementation, or `NULL`.
##

proc br_aes_pwr8_ctrcbc_get_vtable*(): ptr br_block_ctrcbc_class {.importc.}
## *
##  \brief Aggregate structure large enough to be used as context for
##  subkeys (CBC encryption) for all AES implementations.
##

type
  br_aes_gen_cbcenc_keys* {.bycopy, union.} = object
    vtable*: ptr br_block_cbcenc_class
    c_big*: br_aes_big_cbcenc_keys
    c_small*: br_aes_small_cbcenc_keys
    c_ct*: br_aes_ct_cbcenc_keys
    c_ct64*: br_aes_ct64_cbcenc_keys
    c_x86ni*: br_aes_x86ni_cbcenc_keys
    c_pwr8*: br_aes_pwr8_cbcenc_keys


## *
##  \brief Aggregate structure large enough to be used as context for
##  subkeys (CBC decryption) for all AES implementations.
##

type
  br_aes_gen_cbcdec_keys* {.bycopy, union.} = object
    vtable*: ptr br_block_cbcdec_class
    c_big*: br_aes_big_cbcdec_keys
    c_small*: br_aes_small_cbcdec_keys
    c_ct*: br_aes_ct_cbcdec_keys
    c_ct64*: br_aes_ct64_cbcdec_keys
    c_x86ni*: br_aes_x86ni_cbcdec_keys
    c_pwr8*: br_aes_pwr8_cbcdec_keys


## *
##  \brief Aggregate structure large enough to be used as context for
##  subkeys (CTR encryption and decryption) for all AES implementations.
##

type
  br_aes_gen_ctr_keys* {.bycopy, union.} = object
    vtable*: ptr br_block_ctr_class
    c_big*: br_aes_big_ctr_keys
    c_small*: br_aes_small_ctr_keys
    c_ct*: br_aes_ct_ctr_keys
    c_ct64*: br_aes_ct64_ctr_keys
    c_x86ni*: br_aes_x86ni_ctr_keys
    c_pwr8*: br_aes_pwr8_ctr_keys


## *
##  \brief Aggregate structure large enough to be used as context for
##  subkeys (CTR encryption/decryption + CBC-MAC) for all AES implementations.
##

type
  br_aes_gen_ctrcbc_keys* {.bycopy, union.} = object
    vtable*: ptr br_block_ctrcbc_class
    c_big*: br_aes_big_ctrcbc_keys
    c_small*: br_aes_small_ctrcbc_keys
    c_ct*: br_aes_ct_ctrcbc_keys
    c_ct64*: br_aes_ct64_ctrcbc_keys
    c_x86ni*: br_aes_x86ni_ctrcbc_keys
    c_pwr8*: br_aes_pwr8_ctrcbc_keys


##
##  Traditional, table-based implementation for DES/3DES. Since tables are
##  used, cache-timing attacks are conceptually possible.
##
## * \brief DES/3DES block size (8 bytes).

const
  br_des_tab_BLOCK_SIZE* = 8

## *
##  \brief Context for DES subkeys (`des_tab` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_des_tab_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: array[96, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for DES subkeys (`des_tab` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_des_tab_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: array[96, uint32_t]
    num_rounds*: cuint


## *
##  \brief Class instance for DES CBC encryption (`des_tab` implementation).
##

let br_des_tab_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for DES CBC decryption (`des_tab` implementation).
##

let br_des_tab_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Context initialisation (key schedule) for DES CBC encryption
##  (`des_tab` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_des_tab_cbcenc_init*(ctx: ptr br_des_tab_cbcenc_keys; key: pointer;
                            len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for DES CBC decryption
##  (`des_tab` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_des_tab_cbcdec_init*(ctx: ptr br_des_tab_cbcdec_keys; key: pointer;
                            len: csize_t) {.importc.}
## *
##  \brief CBC encryption with DES (`des_tab` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 8).
##

proc br_des_tab_cbcenc_run*(ctx: ptr br_des_tab_cbcenc_keys; iv: pointer;
                           data: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC decryption with DES (`des_tab` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 8).
##

proc br_des_tab_cbcdec_run*(ctx: ptr br_des_tab_cbcdec_keys; iv: pointer;
                           data: pointer; len: csize_t) {.importc.}
##
##  Constant-time implementation for DES/3DES. It is substantially slower
##  (by a factor of about 4x), but also immune to cache-timing attacks.
##
## * \brief DES/3DES block size (8 bytes).

const
  br_des_ct_BLOCK_SIZE* = 8

## *
##  \brief Context for DES subkeys (`des_ct` implementation, CBC encryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_des_ct_cbcenc_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcenc_class ## * \brief Pointer to vtable for this context.
    skey*: array[96, uint32_t]
    num_rounds*: cuint


## *
##  \brief Context for DES subkeys (`des_ct` implementation, CBC decryption).
##
##  First field is a pointer to the vtable; it is set by the initialisation
##  function. Other fields are not supposed to be accessed by user code.
##

type
  br_des_ct_cbcdec_keys* {.bycopy.} = object
    vtable*: ptr br_block_cbcdec_class ## * \brief Pointer to vtable for this context.
    skey*: array[96, uint32_t]
    num_rounds*: cuint


## *
##  \brief Class instance for DES CBC encryption (`des_ct` implementation).
##

let br_des_ct_cbcenc_vtable* {.importc, nodecl.}: br_block_cbcenc_class

## *
##  \brief Class instance for DES CBC decryption (`des_ct` implementation).
##

let br_des_ct_cbcdec_vtable* {.importc, nodecl.}: br_block_cbcdec_class

## *
##  \brief Context initialisation (key schedule) for DES CBC encryption
##  (`des_ct` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_des_ct_cbcenc_init*(ctx: ptr br_des_ct_cbcenc_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief Context initialisation (key schedule) for DES CBC decryption
##  (`des_ct` implementation).
##
##  \param ctx   context to initialise.
##  \param key   secret key.
##  \param len   secret key length (in bytes).
##

proc br_des_ct_cbcdec_init*(ctx: ptr br_des_ct_cbcdec_keys; key: pointer; len: csize_t) {.importc.}
## *
##  \brief CBC encryption with DES (`des_ct` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to encrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 8).
##

proc br_des_ct_cbcenc_run*(ctx: ptr br_des_ct_cbcenc_keys; iv: pointer; data: pointer;
                          len: csize_t) {.importc.}
## *
##  \brief CBC decryption with DES (`des_ct` implementation).
##
##  \param ctx    context (already initialised).
##  \param iv     IV (updated).
##  \param data   data to decrypt (updated).
##  \param len    data length (in bytes, MUST be multiple of 8).
##

proc br_des_ct_cbcdec_run*(ctx: ptr br_des_ct_cbcdec_keys; iv: pointer; data: pointer;
                          len: csize_t) {.importc.}
##
##  These structures are large enough to accommodate subkeys for all
##  DES/3DES implementations.
##
## *
##  \brief Aggregate structure large enough to be used as context for
##  subkeys (CBC encryption) for all DES implementations.
##

type
  br_des_gen_cbcenc_keys* {.bycopy, union.} = object
    vtable*: ptr br_block_cbcenc_class
    tab*: br_des_tab_cbcenc_keys
    ct*: br_des_ct_cbcenc_keys


## *
##  \brief Aggregate structure large enough to be used as context for
##  subkeys (CBC decryption) for all DES implementations.
##

type
  br_des_gen_cbcdec_keys* {.bycopy, union.} = object
    vtable*: ptr br_block_cbcdec_class
    c_tab*: br_des_tab_cbcdec_keys
    c_ct*: br_des_ct_cbcdec_keys


## *
##  \brief Type for a ChaCha20 implementation.
##
##  An implementation follows the description in RFC 7539:
##
##    - Key is 256 bits (`key` points to exactly 32 bytes).
##
##    - IV is 96 bits (`iv` points to exactly 12 bytes).
##
##    - Block counter is over 32 bits and starts at value `cc`; the
##      resulting value is returned.
##
##  Data (pointed to by `data`, of length `len`) is encrypted/decrypted
##  in place. If `len` is not a multiple of 64, then the excess bytes from
##  the last block processing are dropped (therefore, "chunked" processing
##  works only as long as each non-final chunk has a length multiple of 64).
##
##  \param key    secret key (32 bytes).
##  \param iv     IV (12 bytes).
##  \param cc     initial counter value.
##  \param data   data to encrypt or decrypt.
##  \param len    data length (in bytes).
##

type
  br_chacha20_run* = proc (key: pointer; iv: pointer; cc: uint32_t; data: pointer;
                        len: csize_t): uint32_t

## *
##  \brief ChaCha20 implementation (straightforward C code, constant-time).
##
##  \see br_chacha20_run
##
##  \param key    secret key (32 bytes).
##  \param iv     IV (12 bytes).
##  \param cc     initial counter value.
##  \param data   data to encrypt or decrypt.
##  \param len    data length (in bytes).
##

proc br_chacha20_ct_run*(key: pointer; iv: pointer; cc: uint32_t; data: pointer;
                        len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief ChaCha20 implementation (SSE2 code, constant-time).
##
##  This implementation is available only on x86 platforms, depending on
##  compiler support. Moreover, in 32-bit mode, it might not actually run,
##  if the underlying hardware does not implement the SSE2 opcode (in
##  64-bit mode, SSE2 is part of the ABI, so if the code could be compiled
##  at all, then it can run). Use `br_chacha20_sse2_get()` to safely obtain
##  a pointer to that function.
##
##  \see br_chacha20_run
##
##  \param key    secret key (32 bytes).
##  \param iv     IV (12 bytes).
##  \param cc     initial counter value.
##  \param data   data to encrypt or decrypt.
##  \param len    data length (in bytes).
##

proc br_chacha20_sse2_run*(key: pointer; iv: pointer; cc: uint32_t; data: pointer;
                          len: csize_t): uint32_t {.importc, discardable.}
## *
##  \brief Obtain the `sse2` ChaCha20 implementation, if available.
##
##  This function returns a pointer to `br_chacha20_sse2_run`, if
##  that implementation was compiled in the library _and_ the SSE2
##  opcodes are available on the currently running CPU. If either of
##  these conditions is not met, then this function returns `0`.
##
##  \return  the `sse2` ChaCha20 implementation, or `0`.
##

proc br_chacha20_sse2_get*(): br_chacha20_run {.importc.}
## *
##  \brief Type for a ChaCha20+Poly1305 AEAD implementation.
##
##  The provided data is encrypted or decrypted with ChaCha20. The
##  authentication tag is computed on the concatenation of the
##  additional data and the ciphertext, with the padding and lengths
##  as described in RFC 7539 (section 2.8).
##
##  After decryption, the caller is responsible for checking that the
##  computed tag matches the expected value.
##
##  \param key       secret key (32 bytes).
##  \param iv        nonce (12 bytes).
##  \param data      data to encrypt or decrypt.
##  \param len       data length (in bytes).
##  \param aad       additional authenticated data.
##  \param aad_len   length of additional authenticated data (in bytes).
##  \param tag       output buffer for the authentication tag.
##  \param ichacha   implementation of ChaCha20.
##  \param encrypt   non-zero for encryption, zero for decryption.
##

type
  br_poly1305_run* = proc (key: pointer; iv: pointer; data: pointer; len: csize_t;
                        aad: pointer; aad_len: csize_t; tag: pointer;
                        ichacha: br_chacha20_run; encrypt: cint)

## *
##  \brief ChaCha20+Poly1305 AEAD implementation (mixed 32-bit multiplications).
##
##  \see br_poly1305_run
##
##  \param key       secret key (32 bytes).
##  \param iv        nonce (12 bytes).
##  \param data      data to encrypt or decrypt.
##  \param len       data length (in bytes).
##  \param aad       additional authenticated data.
##  \param aad_len   length of additional authenticated data (in bytes).
##  \param tag       output buffer for the authentication tag.
##  \param ichacha   implementation of ChaCha20.
##  \param encrypt   non-zero for encryption, zero for decryption.
##

proc br_poly1305_ctmul_run*(key: pointer; iv: pointer; data: pointer; len: csize_t;
                           aad: pointer; aad_len: csize_t; tag: pointer;
                           ichacha: br_chacha20_run; encrypt: cint) {.importc.}
## *
##  \brief ChaCha20+Poly1305 AEAD implementation (pure 32-bit multiplications).
##
##  \see br_poly1305_run
##
##  \param key       secret key (32 bytes).
##  \param iv        nonce (12 bytes).
##  \param data      data to encrypt or decrypt.
##  \param len       data length (in bytes).
##  \param aad       additional authenticated data.
##  \param aad_len   length of additional authenticated data (in bytes).
##  \param tag       output buffer for the authentication tag.
##  \param ichacha   implementation of ChaCha20.
##  \param encrypt   non-zero for encryption, zero for decryption.
##

proc br_poly1305_ctmul32_run*(key: pointer; iv: pointer; data: pointer; len: csize_t;
                             aad: pointer; aad_len: csize_t; tag: pointer;
                             ichacha: br_chacha20_run; encrypt: cint) {.importc.}
## *
##  \brief ChaCha20+Poly1305 AEAD implementation (i15).
##
##  This implementation relies on the generic big integer code "i15"
##  (which uses pure 32-bit multiplications). As such, it may save a
##  little code footprint in a context where "i15" is already included
##  (e.g. for elliptic curves or for RSA); however, it is also
##  substantially slower than the ctmul and ctmul32 implementations.
##
##  \see br_poly1305_run
##
##  \param key       secret key (32 bytes).
##  \param iv        nonce (12 bytes).
##  \param data      data to encrypt or decrypt.
##  \param len       data length (in bytes).
##  \param aad       additional authenticated data.
##  \param aad_len   length of additional authenticated data (in bytes).
##  \param tag       output buffer for the authentication tag.
##  \param ichacha   implementation of ChaCha20.
##  \param encrypt   non-zero for encryption, zero for decryption.
##

proc br_poly1305_i15_run*(key: pointer; iv: pointer; data: pointer; len: csize_t;
                         aad: pointer; aad_len: csize_t; tag: pointer;
                         ichacha: br_chacha20_run; encrypt: cint) {.importc.}
## *
##  \brief ChaCha20+Poly1305 AEAD implementation (ctmulq).
##
##  This implementation uses 64-bit multiplications (result over 128 bits).
##  It is available only on platforms that offer such a primitive (in
##  practice, 64-bit architectures). Use `br_poly1305_ctmulq_get()` to
##  dynamically obtain a pointer to that function, or 0 if not supported.
##
##  \see br_poly1305_run
##
##  \param key       secret key (32 bytes).
##  \param iv        nonce (12 bytes).
##  \param data      data to encrypt or decrypt.
##  \param len       data length (in bytes).
##  \param aad       additional authenticated data.
##  \param aad_len   length of additional authenticated data (in bytes).
##  \param tag       output buffer for the authentication tag.
##  \param ichacha   implementation of ChaCha20.
##  \param encrypt   non-zero for encryption, zero for decryption.
##

proc br_poly1305_ctmulq_run*(key: pointer; iv: pointer; data: pointer; len: csize_t;
                            aad: pointer; aad_len: csize_t; tag: pointer;
                            ichacha: br_chacha20_run; encrypt: cint) {.importc.}
## *
##  \brief Get the ChaCha20+Poly1305 "ctmulq" implementation, if available.
##
##  This function returns a pointer to the `br_poly1305_ctmulq_run()`
##  function if supported on the current platform; otherwise, it returns 0.
##
##  \return  the ctmulq ChaCha20+Poly1305 implementation, or 0.
##

proc br_poly1305_ctmulq_get*(): br_poly1305_run {.importc.}
