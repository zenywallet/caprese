# Package

version       = "0.1.0"
author        = "zenywallet"
description   = "A front-end web server specialized for real-time message exchange"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim", "a"]
bin           = @["caprese"]


# Dependencies

requires "nim >= 1.6.4"
requires "nimcrypto"
requires "karax"


task bearssl, "Build BearSSL":
  withDir "deps/bearssl":
    exec "make -j$(nproc)"
    exec "mkdir -p ../../src/lib/bearssl"
    exec "cp build/libbearssl.a ../../src/lib/bearssl/"

task openssl, "Build OpenSSL":
  withDir "deps/openssl":
    exec "./Configure"
    exec "make -j$(nproc)"
    exec "mkdir -p ../../src/lib/openssl"
    exec "cp libssl.a ../../src/lib/openssl/"
    exec "cp libcrypto.a ../../src/lib/openssl/"

task libressl, "Build LibreSSL":
  withDir "deps/libressl":
    if dirExists("openbsd"):
      exec "rm -rf openbsd"
    exec "git checkout master"
    exec "git reset --hard"
    exec "git pull"
    exec "./autogen.sh"
    exec "./configure"
    exec "make -j$(nproc)"
    exec "mkdir -p ../../src/lib/libressl"
    exec "cp ssl/.libs/libssl.a ../../src/lib/libressl/"
    exec "cp crypto/.libs/libcrypto.a ../../src/lib/libressl/"

task boringssl, "Build BoringSSL":
  withDir "deps/boringssl":
    mkDir "build"
    cd "build"
    exec "cmake .."
    exec "make -j$(nproc)"
    cd ".."
    exec "mkdir -p ../../src/lib/boringssl"
    exec "cp build/ssl/libssl.a ../../src/lib/boringssl/"
    exec "cp build/crypto/libcrypto.a ../../src/lib/boringssl/"

task deps, "Build deps":
  exec "git submodule update --init"
  bearsslTask()
  opensslTask()
  libresslTask()
  boringsslTask()

before build:
  exec "git submodule update --init"
  if not fileExists("src/lib/bearssl/libbearssl.a"):
    bearsslTask()
  if not fileExists("src/lib/openssl/libssl.a") or not fileExists("src/lib/openssl/libcrypto.a"):
    opensslTask()
  if not fileExists("src/lib/libressl/libssl.a") or not fileExists("src/lib/libressl/libcrypto.a"):
    libresslTask()
  if not fileExists("src/lib/boringssl/libssl.a") or not fileExists("src/lib/boringssl/libcrypto.a"):
    boringsslTask()
