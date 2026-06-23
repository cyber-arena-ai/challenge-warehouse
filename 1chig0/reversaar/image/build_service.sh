#!/usr/bin/env bash
# Build the reversaar service from a source tree.
#
#   build_service.sh <srcdir> [full|fast]
#
# Produces, inside <srcdir>:
#   reversaar.cgi   the plain-CGI main binary (served via fcgiwrap)
#   .tmp.bin        the encrypted array.so blob that /api/array dlopen()s
#
# Modes:
#   full  (image-build only) runs the upstream obfuscation codegen
#         (obfuscate.py over *.c/*.h: strcmp->crc32 + string XOR) BEFORE
#         compiling. obfuscate.py rewrites sources in place and leaves *.bak
#         backups, so it is only safe on a pristine tree (the image build copies
#         one into /tmp). This proves the full upstream pipeline at bake time.
#   fast  (defense rebuild, the default) compiles the source AS-IS (no
#         obfuscation) so the agent edits readable C and rebuilds deterministically
#         and offline. The vuln/defense semantics are identical either way;
#         obfuscation is only a reversing-difficulty layer.
#
# In BOTH modes the array.so -> forge_crc32 -> rc4wrap chain runs, because the
# runtime decrypts .tmp.bin (RC4 key "ThereIsNoBackdoor", CRC self-reference).
set -eu

SRC="${1:?usage: build_service.sh <srcdir> [full|fast]}"
MODE="${2:-fast}"
cd "$SRC/src"

CFLAGS="-Wall -O2"
CGI_LIBS="-lfcgi -ljson-c -lz -luuid -ldl"
SO_LIBS="-lfcgi -ljson-c -lz -luuid"

if [ "$MODE" = "full" ]; then
    python3 obfuscate.py *.c *.h
fi

# main CGI binary
gcc $CFLAGS -o reversaar.cgi main.c crypto/sha256.c crypto/base64.c crypto/arcfour.c $CGI_LIBS
strip -s reversaar.cgi

# array plugin -> forged CRC -> RC4-wrapped blob (.tmp.bin)
gcc -fvisibility=hidden -shared -fPIC $CFLAGS -o array.so array.c crypto/sha256.c crypto/base64.c $SO_LIBS
strip -s array.so
cp array.so array.forged.so
python3 forge_crc32.py array.forged.so
cp array.forged.so array.encrypted.so
python3 rc4wrap.py array.encrypted.so
mv array.encrypted.so "$SRC/.tmp.bin"
mv reversaar.cgi "$SRC/reversaar.cgi"

# tidy intermediate build products + obfuscation backups
rm -f array.so array.forged.so array.forged.so.bak array.encrypted.so.bak ./*.bak ./crypto/*.bak 2>/dev/null || true

echo "build_service: built reversaar.cgi + .tmp.bin (mode=$MODE)"
