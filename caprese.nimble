# Package

version       = "0.1.0"
author        = "zenywallet"
description   = "A front-end web server specialized for real-time message exchange"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim", "a", "jar"]
installDirs   = @["bin", "brotli", "zopfli"]
bin           = @["caprese"]


# Dependencies

requires "nim >= 1.6.4"
when NimMajor >= 2:
  requires "checksums"
requires "karax >= 1.2.3"
requires "regex"


task bearssl, "Build BearSSL":
  withDir "deps/bearssl":
    exec "make -j$(nproc --all || sysctl -n hw.ncpu || getconf _NPROCESSORS_ONLN || echo 1)"
    exec "mkdir -p ../../src/lib/bearssl"
    exec "cp build/libbearssl.a ../../src/lib/bearssl/"

task openssl, "Build OpenSSL":
  withDir "deps/openssl":
    if fileExists("libssl.so"):
      exec "make clean"
    exec "./Configure no-shared"
    exec "make -j$(nproc --all || sysctl -n hw.ncpu || getconf _NPROCESSORS_ONLN || echo 1)"
    exec "mkdir -p ../../src/lib/openssl"
    exec "cp libssl.a ../../src/lib/openssl/"
    exec "cp libcrypto.a ../../src/lib/openssl/"
    exec "cp apps/openssl ../../src/lib/openssl/"

task libressl, "Build LibreSSL":
  withDir "deps/libressl":
    if dirExists("openbsd"):
      exec "rm -rf openbsd"
    exec "git checkout master"
    exec "git reset --hard"
    exec "git pull"
    exec "./autogen.sh"
    exec "./configure"
    exec "make -j$(nproc --all || sysctl -n hw.ncpu || getconf _NPROCESSORS_ONLN || echo 1)"
    exec "mkdir -p ../../src/lib/libressl"
    exec "cp ssl/.libs/libssl.a ../../src/lib/libressl/"
    exec "cp crypto/.libs/libcrypto.a ../../src/lib/libressl/"

task boringssl, "Build BoringSSL":
  withDir "deps/boringssl":
    mkDir "build"
    cd "build"
    exec "cmake .."
    exec "make -j$(nproc --all || sysctl -n hw.ncpu || getconf _NPROCESSORS_ONLN || echo 1)"
    cd ".."
    exec "mkdir -p ../../src/lib/boringssl"
    if fileExists("build/libssl.a"):
      exec "cp build/libssl.a ../../src/lib/boringssl/"
      exec "cp build/libcrypto.a ../../src/lib/boringssl/"
    else:
      exec "cp build/ssl/libssl.a ../../src/lib/boringssl/"
      exec "cp build/crypto/libcrypto.a ../../src/lib/boringssl/"

task selfcert, "Generate Self-Signed Certificate":
  exec "nim c -r src/caprese/self_cert.nim"

task zopfli, "Copy zopfli":
  withDir "deps/zopfli":
    exec "mkdir -p ../../src/zopfli"
    exec "cp src/zopfli/* ../../src/zopfli/"

task brotli, "Copy brotli":
  withDir "deps/brotli":
    exec "mkdir -p ../../src/brotli"
    exec "cp -r c ../../src/brotli/"

task depsAll, "Build deps":
  if getEnv("NOREMOTEUPDATE") == "1":
    exec "git submodule update --init"
  else:
    exec "git submodule update --init --remote"
  bearsslTask()
  opensslTask()
  libresslTask()
  boringsslTask()
  selfcertTask()
  zopfliTask()
  brotliTask()

task missingFileWorkaround, "Missing File Workaround":
  withDir "src":
    exec "mkdir -p src/bin"
    exec "mkdir -p src/brotli"
    exec "mkdir -p src/zopfli"
    exec "touch src/bin/empty.a"
    exec "touch src/brotli/empty.a"
    exec "touch src/zopfli/empty.a"
    exec "touch src/THIS_FOLDER_FOR_MISSING_FILE_WORKAROUND.a"

before install:
  missingFileWorkaroundTask()

before build:
  if getEnv("NOSSL") == "1":
    if getEnv("NOREMOTEUPDATE") == "1":
      exec "git submodule update --init deps/zopfli"
      exec "git submodule update --init deps/brotli"
      exec "git submodule update --init deps/bearssl"
    else:
      exec "git submodule update --init --remote deps/zopfli"
      exec "git submodule update --init --remote deps/brotli"
      exec "git submodule update --init --remote deps/bearssl"
    if not fileExists("src/lib/bearssl/libbearssl.a"):
      bearsslTask()
    exec "mkdir -p src/lib"
    exec "touch src/lib/NOSSL.a"
  else:
    if getEnv("NOREMOTEUPDATE") == "1":
      exec "git submodule update --init"
    else:
      exec "git submodule update --init --remote"
    if not fileExists("src/lib/bearssl/libbearssl.a"):
      bearsslTask()
    if not fileExists("src/lib/openssl/libssl.a") or not fileExists("src/lib/openssl/libcrypto.a"):
      opensslTask()
    if not fileExists("src/lib/libressl/libssl.a") or not fileExists("src/lib/libressl/libcrypto.a"):
      libresslTask()
    if not fileExists("src/lib/boringssl/libssl.a") or not fileExists("src/lib/boringssl/libcrypto.a"):
      boringsslTask()
    selfcertTask()
    exec "rm -f src/lib/NOSSL.a"
  zopfliTask()
  brotliTask()
