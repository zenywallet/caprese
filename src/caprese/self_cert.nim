# Copyright (c) 2024 zenywallet

import openssl

type
  SelfCertError* = object of CatchableError

proc generateCert() =
  var x509: X509 = X509_new()
  var pkey: EVP_PKEY = EVP_PKEY_new()
  var rsa: RSA = RSA_new()
  var exp: BIGNUM = BN_new()
  var big: BIGNUM = BN_new()
  var serial: ASN1_INTEGER = ASN1_INTEGER_new()

  defer:
    ASN1_INTEGER_free(serial)
    BN_free(big)
    BN_free(exp)
    if not rsa.isNil: RSA_free(rsa)
    EVP_PKEY_free(pkey)
    X509_free(x509)

  template checkErr(err: cint) {.dirty.} =
    if err == 0:
      raise newException(SelfCertError, "self certificate check error")

  template checkErr(retFlag: bool) {.dirty.} =
    if not retFlag:
      raise newException(SelfCertError, "self certificate check error")

  checkErr BN_set_word(exp, RSA_F4)
  checkErr RSA_generate_key_ex(rsa, 2048, exp, nil)
  checkErr BN_pseudo_rand(big, 64, 0, 0)
  BN_to_ASN1_INTEGER(big, serial)
  checkErr X509_set_serialNumber(x509, serial)
  checkErr EVP_PKEY_assign_RSA(pkey, rsa)
  rsa = nil
  checkErr PEM_write_PrivateKey(stdout, pkey, nil, nil, 0, nil, nil)


generateCert()
