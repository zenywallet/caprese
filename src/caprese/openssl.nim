# Copyright (c) 2021 zenywallet

import os

const USE_LIBRESSL = defined(USE_LIBRESSL)
const USE_BORINGSSL = defined(USE_BORINGSSL)

when USE_LIBRESSL:
  const libresslPath* = currentSourcePath.parentDir() / "../lib/libressl"
  {.passL: libresslPath / "libssl.a".}
  {.passL: libresslPath / "libcrypto.a".}
elif USE_BORINGSSL:
  const boringsslPath* = currentSourcePath.parentDir() / "../lib/boringssl"
  {.passL: boringsslPath / "libssl.a".}
  {.passL: boringsslPath / "libcrypto.a".}
else:
  const opensslPath* = currentSourcePath.parentDir() / "../lib/openssl"
  {.passL: opensslPath / "libssl.a".}
  {.passL: opensslPath / "libcrypto.a".}

type
  # include/internal/conf.h
  ossl_init_settings_st = ptr object

  # ssl/ssl_local.h
  ssl_st = ptr object
  ssl_ctx_st = ptr object
  ssl_method_st = ptr object

  # include/openssl/types.h
  OPENSSL_INIT_SETTINGS* = ossl_init_settings_st
  SSL* = ssl_st
  SSL_CTX* = ssl_ctx_st
  SSL_METHOD* = ssl_method_st

# include/openssl/x509.h
const X509_FILETYPE_PEM* = 1

# include/openssl/ssl.h
const OPENSSL_INIT_NO_LOAD_SSL_STRINGS* = 0x00100000'u64
const OPENSSL_INIT_LOAD_SSL_STRINGS* = 0x00200000'u64

const SSL_FILETYPE_PEM* = X509_FILETYPE_PEM

const SSL_OP_NO_SSLv3* = 0x02000000'u32
const SSL_OP_NO_TLSv1* = 0x04000000'u32
const SSL_OP_NO_TLSv1_2* = 0x08000000'u32
const SSL_OP_NO_TLSv1_1* = 0x10000000'u32
const SSL_OP_NO_TLSv1_3* = 0x20000000'u32

# Removed from OpenSSL 1.1.0. Was 0x01000000L
const SSL_OP_NO_SSLv2* = 0x0'u32


const SSL_MODE_ENABLE_PARTIAL_WRITE* = 0x00000001'u64
const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER* = 0x00000002'u64
when USE_BORINGSSL:
  const SSL_MODE_NO_AUTO_CHAIN* = 0x00000008'u64
  const SSL_MODE_AUTO_RETRY* = 0
  const SSL_MODE_RELEASE_BUFFERS* = 0
  const SSL_MODE_SEND_CLIENTHELLO_TIME* = 0
  const SSL_MODE_SEND_SERVERHELLO_TIME* = 0
  const SSL_MODE_SEND_FALLBACK_SCSV* = 0x00000400'u64
else:
  const SSL_MODE_AUTO_RETRY* = 0x00000004'u64
  const SSL_MODE_RELEASE_BUFFERS* = 0x00000010'u64
  const SSL_MODE_SEND_CLIENTHELLO_TIME* = 0x00000020'u64
  const SSL_MODE_SEND_SERVERHELLO_TIME* = 0x00000040'u64
  const SSL_MODE_SEND_FALLBACK_SCSV* = 0x00000080'u64
  const SSL_CTRL_MODE* = 33
  const SSL_CTRL_CLEAR_MODE* = 78

const SSL_ERROR_NONE* = 0
const SSL_ERROR_SSL* = 1
const SSL_ERROR_WANT_READ* = 2
const SSL_ERROR_WANT_WRITE* = 3
const SSL_ERROR_WANT_X509_LOOKUP* = 4
const SSL_ERROR_SYSCALL* = 5
const SSL_ERROR_ZERO_RETURN* = 6
const SSL_ERROR_WANT_CONNECT* = 7
const SSL_ERROR_WANT_ACCEPT* = 8
const SSL_ERROR_WANT_ASYNC* = 9
const SSL_ERROR_WANT_ASYNC_JOB* = 10
const SSL_ERROR_WANT_CLIENT_HELLO_CB* = 11
const SSL_ERROR_WANT_RETRY_VERIFY* = 12

# include/openssl/crypto.h
const OPENSSL_VERSION_0* = 0
const OPENSSL_CFLAGS* = 1
const OPENSSL_BUILT_ON* = 2
const OPENSSL_PLATFORM* = 3
const OPENSSL_DIR* = 4
const OPENSSL_ENGINES_DIR* = 5
const OPENSSL_VERSION_STRING* = 6
const OPENSSL_FULL_VERSION_STRING* = 7
const OPENSSL_MODULES_DIR* = 8
const OPENSSL_CPU_INFO* = 9

const OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS* = 0x00000001'u64
const OPENSSL_INIT_LOAD_CRYPTO_STRINGS* = 0x00000002'u64
const OPENSSL_INIT_ADD_ALL_CIPHERS* = 0x00000004'u64
const OPENSSL_INIT_ADD_ALL_DIGESTS* = 0x00000008'u64

# include/openssl/ssl.h
proc TLS_server_method*(): SSL_METHOD {.importc, cdecl.}
proc SSLv23_server_method*(): SSL_METHOD {.inline.} = TLS_server_method()
proc SSL_CTX_new*(meth: SSL_METHOD): SSL_CTX {.importc, cdecl.}
proc SSL_CTX_free*(ctx: SSL_CTX) {.importc, cdecl.}
proc SSL_new*(ctx: SSL_CTX): SSL {.importc, cdecl.}

proc OPENSSL_init_ssl*(opts: uint64, settings: OPENSSL_INIT_SETTINGS): cint {.importc, cdecl.}
proc SSL_library_init*(): cint {.inline, discardable.} = OPENSSL_init_ssl(0'u64, nil)
proc SSL_load_error_strings*(): cint {.inline, discardable.} =
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil)

proc SSL_CTX_use_PrivateKey_file*(ctx: SSL_CTX, file: cstring, fileType: cint): cint {.importc, cdecl.}
proc SSL_CTX_use_certificate_file*(ctx: SSL_CTX, file: cstring, fileType: cint): cint {.importc, cdecl.}
proc SSL_CTX_use_certificate_chain_file*(ctx: SSL_CTX, file: cstring): cint {.importc, cdecl.}

proc SSL_set_fd*(s: SSL, fd: cint): cint {.importc, cdecl.}
proc SSL_free*(ssl: SSL) {.importc, cdecl.}
proc SSL_accept*(ssl: SSL): cint {.importc, cdecl.}
proc SSL_stateless*(s: SSL): cint {.importc, cdecl.}
proc SSL_connect*(ssl: SSL): cint {.importc, cdecl.}
proc SSL_read*(ssl: SSL, buf: pointer, num: cint): cint {.importc, cdecl.}
proc SSL_read_ex*(ssl: SSL, buf: pointer, num: csize_t, readbytes: csize_t): cint {.importc, cdecl.}

proc SSL_write*(ssl: SSL, buf: pointer, num: cint): cint {.importc, cdecl.}
proc SSL_write_ex*(s: SSL, buf: pointer, num: csize_t, written: csize_t): cint {.importc, cdecl.}
proc SSL_write_early_data*(s: SSL, buf: pointer, num: csize_t, written: csize_t): cint {.importc, cdecl.}

when not USE_BORINGSSL:
  proc SSL_ctrl*(ssl: SSL, cmd: cint, larg: clong, parg: pointer): clong {.importc, cdecl, discardable.}
  proc SSL_CTX_ctrl*(ctx: SSL_CTX, cmd: cint, larg: clong, parg: pointer): clong {.importc, cdecl, discardable.}

when USE_LIBRESSL:
  const SSL_CTRL_OPTIONS* = 32
  template SSL_CTX_set_options*(ctx, op: untyped): untyped =
    SSL_CTX_ctrl((ctx), SSL_CTRL_OPTIONS, (op), nil)
else:
  proc SSL_CTX_set_options*(ctx: SSL_CTX, op: clong): clong {.importc, cdecl, discardable.}

when USE_BORINGSSL:
  proc SSL_CTX_set_mode*(ctx: SSL_CTX, mode: clong): clong {.importc, cdecl, discardable.}
  proc SSL_CTX_clear_mode*(ctx: SSL_CTX; mode: clong): clong {.importc, cdecl, discardable.}
  proc SSL_CTX_get_mode*(ctx: SSL_CTX): clong {.importc, cdecl.}
  proc SSL_set_mode*(ssl: SSL, mode: clong): clong {.importc, cdecl, discardable.}
  proc SSL_clear_mode*(ssl: SSL; mode: clong): clong {.importc, cdecl, discardable.}
  proc SSL_get_mode*(ssl: SSL): clong {.importc, cdecl.}
else:
  proc SSL_CTX_set_mode*(ctx: SSL_CTX, mode: clong): clong {.inline, discardable.} =
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, mode, nil)
  proc SSL_CTX_clear_mode*(ctx: SSL_CTX, mode: clong): clong {.inline, discardable.} =
    SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, mode, nil)
  proc SSL_CTX_get_mode*(ctx: SSL_CTX): clong {.inline.} =
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, 0, nil)
  proc SSL_set_mode*(ssl: SSL, mode: clong): clong {.inline, discardable.} =
    SSL_ctrl(ssl, SSL_CTRL_MODE, mode, nil)
  proc SSL_clear_mode*(ssl: SSL, mode: clong): clong {.inline, discardable.} =
    SSL_ctrl(ssl, SSL_CTRL_CLEAR_MODE, mode, nil)
  proc SSL_get_mode*(ssl: SSL): clong {.inline.} =
    SSL_ctrl(ssl, SSL_CTRL_MODE, 0, nil)

proc SSL_get_error*(s: SSL, ret_code: cint): cint {.importc, cdecl.}
proc SSL_get_version*(s: SSL): cstring {.importc, cdecl.}

# include/openssl/crypto.h
proc OpenSSL_version*(t: cint): cstring {.importc, cdecl.}
proc OPENSSL_init_crypto*(opts: uint64, settings: OPENSSL_INIT_SETTINGS): cint {.importc, cdecl.}

# include/openssl/evp.h
proc OPENSSL_add_all_algorithms_noconf*(): cint {.inline.} =
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS, nil)
proc OpenSSL_add_all_algorithms*(): cint {.inline, discardable.} = OPENSSL_add_all_algorithms_noconf()

# include/openssl/err.h
proc ERR_get_error*(): culong {.importc, cdecl.}
proc ERR_peek_error*(): culong {.importc, cdecl.}
proc ERR_clear_error*() {.importc, cdecl.}


# SNI
# include/openssl/ssl.h
when not USE_BORINGSSL:
  const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB* = 53
  proc SSL_callback_ctrl*(a1: SSL; a2: cint; a3: proc () {.cdecl.}): clong {.importc, cdecl, discardable.}
  proc SSL_CTX_callback_ctrl*(a1: SSL_CTX; a2: cint; a3: proc () {.cdecl.}): clong {.importc, cdecl, discardable.}

proc SSL_set_SSL_CTX*(ssl: SSL; ctx: SSL_CTX): SSL_CTX {.importc, cdecl.}

# include/openssl/tls1.h
const TLSEXT_NAMETYPE_host_name* = 0
proc SSL_get_servername*(s: SSL; `type`: cint): cstring {.importc, cdecl.}

when USE_BORINGSSL:
  proc SSL_CTX_set_tlsext_servername_callback*(ctx: SSL_CTX;
    callback: proc (ssl: SSL; out_alert: ptr cint; arg: pointer): cint {.cdecl.}): cint {.importc, cdecl, discardable.}
else:
  proc SSL_CTX_set_tlsext_servername_callback*(ctx: SSL_CTX;
    cb: proc (ssl: SSL; out_alert: ptr cint; arg: pointer): cint {.cdecl.}): clong {.inline, discardable.} =
    return SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cast[proc () {.cdecl.}](cb))

const
  SSL_TLSEXT_ERR_OK* = 0
  SSL_TLSEXT_ERR_ALERT_WARNING* = 1
  SSL_TLSEXT_ERR_ALERT_FATAL* = 2
  SSL_TLSEXT_ERR_NOACK* = 3


# self-signed certificate
# include/openssl/type.h
type
  EVP_PKEY* = ptr object
  ASN1_INTEGER* = ptr object
  BIGNUM* = ptr object
  BN_GENCB* = ptr object
  X509* = ptr object
  X509_NAME* = ptr object
  X509_CRL* = ptr object
  ASN1_TIME* = ptr object
  EVP_MD* = ptr object

# include/openssl/ssl.h
proc SSL_CTX_use_PrivateKey*(ctx: SSL_CTX, pkey: EVP_PKEY): cint {.importc, cdecl.}
proc SSL_CTX_use_certificate*(ctx: SSL_CTX, x: X509): cint {.importc, cdecl.}

# include/openssl/rsa.h
type
  RSA* = ptr object

const RSA_F4* = 0x10001.culong

proc RSA_new*(): RSA {.importc, cdecl.}
proc RSA_free*(rsa: RSA) {.importc, cdecl.}
proc RSA_generate_key_ex*(rsa: RSA, bits: cint, e: BIGNUM, cb: BN_GENCB): cint {.importc, cdecl.}
proc RSA_generate_multi_prime_key*(rsa: RSA, bits: cint, primes: cint, e: BIGNUM, cb: BN_GENCB): cint {.importc, cdecl.}

# include/openssl/evp.h
const EVP_PKEY_RSA* = 6.cint

proc EVP_PKEY_new*(): EVP_PKEY {.importc, cdecl.}
proc EVP_PKEY_free*(key: EVP_PKEY) {.importc, cdecl.}
proc EVP_PKEY_assign*(pkey: EVP_PKEY, keytype: cint, key: RSA): cint {.importc, cdecl.}
proc EVP_PKEY_assign_RSA*(pkey: EVP_PKEY, key: RSA): cint {.inline.} = EVP_PKEY_assign(pkey, EVP_PKEY_RSA, key)
proc EVP_PKEY_set1_RSA*(pkey: EVP_PKEY, key: RSA): cint {.importc, cdecl.}
proc EVP_sha1*(): EVP_MD {.importc, cdecl.}

proc i2d_PrivateKey*(a: EVP_PKEY; pp: ptr ptr cuchar): cint {.importc, cdecl.}

# include/openssl/asn1.h
const MBSTRING_FLAG* = 0x1000.cint
const MBSTRING_UTF8* = MBSTRING_FLAG
const MBSTRING_ASC* = MBSTRING_FLAG or 1.cint
const MBSTRING_BMP* = MBSTRING_FLAG or 2.cint
const MBSTRING_UNIV* = MBSTRING_FLAG or 4.cint

proc ASN1_INTEGER_new*(): ASN1_INTEGER {.importc, cdecl.}
proc ASN1_INTEGER_free*(a: ASN1_INTEGER) {.importc, cdecl.}

proc ASN1_INTEGER_set_int64*(a: ASN1_INTEGER, r: int64): cint {.importc, cdecl.}
proc ASN1_INTEGER_set_uint64*(a: ASN1_INTEGER, r: uint64): cint {.importc, cdecl.}
proc ASN1_INTEGER_set*(a: ASN1_INTEGER, v: clong): cint {.importc, cdecl.}

proc ASN1_INTEGER_get_int64*(pr: var int64, a: ASN1_INTEGER): cint {.importc, cdecl.}
proc ASN1_INTEGER_get_uint64*(pr: var uint64, a: ASN1_INTEGER): cint {.importc, cdecl.}
proc ASN1_INTEGER_get*(a: ASN1_INTEGER): clong {.importc, cdecl.}
proc BN_to_ASN1_INTEGER*(bn: BIGNUM, ai: ASN1_INTEGER): ASN1_INTEGER {.importc, cdecl, discardable.}
proc ASN1_INTEGER_to_BN*(ai: ASN1_INTEGER, bn: BIGNUM): BIGNUM {.importc, cdecl, discardable.}

# include/openssl/bn.h
type
  BN_ULONG* = uint64

proc BN_new*(): BIGNUM {.importc, cdecl.}
proc BN_secure_new*(): BIGNUM {.importc, cdecl.}
proc BN_clear*(a: BIGNUM) {.importc, cdecl.}
proc BN_free*(a: BIGNUM) {.importc, cdecl.}
proc BN_clear_free*(a: BIGNUM) {.importc, cdecl.}

proc BN_zero*(a: BIGNUM) {.importc, cdecl.}
proc BN_one*(a: BIGNUM): cint {.importc, cdecl.}
proc BN_value_one*(): BIGNUM {.importc, cdecl.}
proc BN_set_word*(a: BIGNUM, w: BN_ULONG): cint {.importc, cdecl.}
proc BN_get_word*(a: BIGNUM): BN_ULONG {.importc, cdecl.}

proc BN_rand*(rnd: BIGNUM, bits: cint, top: cint, bottom: cint): cint {.importc, cdecl.}
proc BN_priv_rand*(rnd: BIGNUM, bits: cint, top: cint, bottom: cint): cint {.importc, cdecl.}
proc BN_pseudo_rand*(rnd: BIGNUM, bits: cint, top: cint, bottom: cint): cint {.importc, cdecl.}
proc BN_rand_range*(rnd: BIGNUM, range: BIGNUM): cint {.importc, cdecl.}
proc BN_priv_rand_range*(rnd: BIGNUM, range: BIGNUM): cint {.importc, cdecl.}
proc BN_pseudo_rand_range*(rnd: BIGNUM, range: BIGNUM): cint {.importc, cdecl.}

# include/openssl/x509.h
type
  X509_REQ* = ptr object

proc X509_new*(): X509 {.importc, cdecl.}
proc X509_free*(a: X509) {.importc, cdecl.}
proc X509_get_subject_name*(x: X509): X509_NAME {.importc, cdecl.}
proc X509_set_subject_name*(x: X509, name: X509_NAME): cint {.importc, cdecl.}
proc X509_get_issuer_name*(x: X509): X509_NAME {.importc, cdecl.}
proc X509_set_issuer_name*(x: X509, name: X509_NAME): cint {.importc, cdecl.}
proc X509_REQ_get_subject_name*(x: X509_REQ): X509_NAME {.importc, cdecl.}
proc X509_REQ_set_subject_name*(x: X509_REQ, name: X509_NAME): cint {.importc, cdecl.}
proc X509_CRL_get_issuer*(x: X509_CRL): X509_NAME {.importc, cdecl.}
proc X509_CRL_set_issuer_name*(x: X509_CRL, name: X509_NAME): cint {.importc, cdecl.}

proc X509_get_serialNumber*(x: X509): ASN1_INTEGER {.importc, cdecl.}
proc X509_get0_serialNumber*(x: X509): ASN1_INTEGER {.importc, cdecl.}
proc X509_set_serialNumber*(x: X509, serial: ASN1_INTEGER): cint {.importc, cdecl.}

proc X509_get_version*(x: X509): clong {.importc, cdecl.}
proc X509_set_version*(x: X509, version: clong): cint {.importc, cdecl.}

proc X509_gmtime_adj*(s: ASN1_TIME, adj: clong): ASN1_TIME {.importc, cdecl, discardable.}
proc X509_get_notBefore*(x: X509): ASN1_TIME {.importc: "X509_getm_notBefore", cdecl.}
proc X509_get_notAfter*(x: X509): ASN1_TIME {.importc: "X509_getm_notAfter", cdecl.}

proc X509_set_pubkey*(x: X509, pkey: EVP_PKEY): cint {.importc, cdecl.}

proc X509_NAME_add_entry_by_txt*(name: X509_NAME , field: cstring, stype: cint,
                               bytes: cstring, len: cint, loc: cint,
                               set: cint): cint {.importc, cdecl.}
proc X509_sign*(x: X509, pkey: EVP_PKEY, md: EVP_MD): cint {.importc, cdecl.}
proc i2d_X509*(x: X509; ppout: ptr ptr cuchar): cint {.importc, cdecl.}

# SAN
# include/openssl/x509.h
type
  X509_EXTENSION* = ptr object

proc X509_add_ext*(x: X509; ex: X509_EXTENSION; loc: cint): cint {.importc, cdecl.}
proc X509_EXTENSION_free*(ex: X509_EXTENSION) {.importc, cdecl.}

# include/openssl/x509v3.h
type
  X509V3_CONF_METHOD* = ptr object

  v3_ext_ctx* {.bycopy.} = object
    flags*: cint
    issuer_cert*: X509
    subject_cert*: X509
    subject_req*: X509_REQ
    crl*: X509_CRL
    db_meth*: X509V3_CONF_METHOD
    db*: pointer
    issuer_pkey*: EVP_PKEY
    # Maybe more here

const
  X509V3_CTX_TEST* = 0x1
  X509V3_CTX_REPLACE* = 0x2

# include/openssl/type.h
type
  X509V3_CTX* = ptr v3_ext_ctx
  CONF = ptr object

# include/openssl/x509v3.h
proc X509V3_EXT_nconf_nid*(conf: CONF; ctx: X509V3_CTX; ext_nid: cint;
                           value: cstring): X509_EXTENSION {.importc, cdecl.}
proc X509V3_set_ctx*(ctx: X509V3_CTX, issuer: X509,  subject: X509,
                     req: X509_REQ, crl: X509_CRL, flags: cint) {.importc, cdecl.}

# include/openssl/obj_mac.h
const
  NID_subject_key_identifier* = 82
  NID_subject_alt_name* = 85
  NID_basic_constraints* = 87
  NID_authority_key_identifier* = 90

# include/crypto/evp.h
type
  evp_cipher_st = ptr object

# include/openssl/types.h
type
  EVP_CIPHER = evp_cipher_st

# include/openssl/pem.h
type
  pem_password_cb* = proc (buf: cstring; size: cint; rwflag: cint; u: pointer): cint {.cdecl.}

proc PEM_write_X509*(fp: File; x: X509): cint {.importc, cdecl.}
proc PEM_write_PrivateKey*(fp: File; x: EVP_PKEY; enc: EVP_CIPHER;
                          kstr: ptr cuchar; klen: cint; cb: pem_password_cb;
                          u: pointer): cint {.importc, cdecl.}

when isMainModule:
  echo SSL_load_error_strings()
  echo SSL_library_init()
  echo OpenSSL_add_all_algorithms()

  var ctx = SSL_CTX_new(TLS_server_method())
  echo repr ctx
  echo SSL_CTX_set_options(ctx, (SSL_OP_NO_SSLv2 or SSL_OP_NO_SSLv3 or
                      SSL_OP_NO_TLSv1 or SSL_OP_NO_TLSv1_1 or SSL_OP_NO_TLSv1_2).clong)
  var ssl = SSL_new(ctx)
  echo repr ssl
  echo SSL_get_version(ssl)
  for i in 0..9:
    echo OpenSSL_version(i.cint)
