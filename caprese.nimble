# Package

version       = "0.1.0"
author        = "zenywallet"
description   = "A front-end web server specialized for real-time message exchange"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @["caprese"]


# Dependencies

requires "nim >= 1.6.4"
requires "nimcrypto"
requires "karax"


task deps, "Build deps":
  withDir "deps/bearssl":
    exec "make -j$(nproc)"

task openssl, "Build OpenSSL":
  withDir "deps/openssl":
    exec "./Configure"
    exec "make -j$(nproc)"

task libressl, "Build LibreSSL":
  withDir "deps/libressl":
    if dirExists("openbsd"):
      exec "rm -rf openbsd"
    exec "git checkout master"
    exec "./autogen.sh"
    exec "./configure"
    exec "make -j$(nproc)"

task boringssl, "Build BoringSSL":
  withDir "deps/boringssl":
    mkDir "build"
    cd "build"
    exec "cmake .."
    exec "make -j$(nproc)"
