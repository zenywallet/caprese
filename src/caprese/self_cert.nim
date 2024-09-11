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


  checkErr X509_set_version(x509, 2)
  X509_gmtime_adj(X509_get_notBefore(x509), -60 * 60)
  X509_gmtime_adj(X509_get_notAfter(x509), 60 * 60 * 24 * 365 * 10)
  checkErr X509_set_pubkey(x509, pkey)

  var name: X509_NAME = X509_get_subject_name(x509)
  checkErr X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "JP", -1, -1, 0)
  checkErr X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Caprese Self-Signed Certificate", -1, -1, 0)
  checkErr X509_set_issuer_name(x509, name)

  var v3CtxObj: v3_ext_ctx
  var v3Ctx: X509V3_CTX = addr v3CtxObj
  X509V3_set_ctx(v3Ctx, x509, x509, nil, nil, 0)
  var subjectAltName = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_subject_alt_name, "DNS:localhost".cstring)
  checkErr X509_add_ext(x509, subjectAltName, -1)
  X509_EXTENSION_free(subjectAltName)
  var basicConstraints = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_basic_constraints, "critical,CA:FALSE".cstring)
  checkErr X509_add_ext(x509, basicConstraints, -1)
  X509_EXTENSION_free(basicConstraints)
  var subjectKeyIdentifier = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_subject_key_identifier, "hash".cstring)
  checkErr X509_add_ext(x509, subjectKeyIdentifier, -1)
  X509_EXTENSION_free(subjectKeyIdentifier)
  var authorityKeyIdentifier = X509V3_EXT_nconf_nid(nil, v3Ctx, NID_authority_key_identifier, "keyid:always".cstring)
  checkErr X509_add_ext(x509, authorityKeyIdentifier, -1)
  X509_EXTENSION_free(authorityKeyIdentifier)

  checkErr X509_sign(x509, pkey, EVP_sha1())
  checkErr PEM_write_X509(stdout, x509)


generateCert()
