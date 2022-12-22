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
  bearsslTask()
  opensslTask()
  libresslTask()
  boringsslTask()
