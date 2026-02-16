#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/target/swift"

cd "$ROOT_DIR"

cargo build -p common -p server -p client

mkdir -p "$OUT_DIR/common" "$OUT_DIR/server" "$OUT_DIR/client"

cargo run -q -p uniffi-bindgen -- generate \
  --language swift \
  --out-dir "$OUT_DIR/common" \
  "$ROOT_DIR/target/debug/libcommon.dylib"

cargo run -q -p uniffi-bindgen -- generate \
  --language swift \
  --config "$ROOT_DIR/server/uniffi.toml" \
  --out-dir "$OUT_DIR/server" \
  "$ROOT_DIR/target/debug/libserver.dylib"

# UniFFI 0.31 with external Swift package bindings may omit importing the common
# FFI module from the server/client module files. In explicit-module Xcode builds,
# this can fail with "missing import of defining module 'DeskheldFFI'".
perl -0777 -i -pe 's/#if canImport\(DeskheldServerFFI\)\nimport DeskheldServerFFI\n#endif/#if canImport(DeskheldServerFFI)\nimport DeskheldServerFFI\n#endif\n#if canImport(DeskheldFFI)\nimport DeskheldFFI\n#endif/' "$OUT_DIR/server/DeskheldServer.swift"

cargo run -q -p uniffi-bindgen -- generate \
  --language swift \
  --config "$ROOT_DIR/client/uniffi.toml" \
  --out-dir "$OUT_DIR/client" \
  "$ROOT_DIR/target/debug/libclient.dylib"

perl -0777 -i -pe 's/#if canImport\(DeskheldClientFFI\)\nimport DeskheldClientFFI\n#endif/#if canImport(DeskheldClientFFI)\nimport DeskheldClientFFI\n#endif\n#if canImport(DeskheldFFI)\nimport DeskheldFFI\n#endif/' "$OUT_DIR/client/DeskheldClient.swift"

echo "Swift bindings generated in $OUT_DIR"
