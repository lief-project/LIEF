#!/bin/bash
# Compile the Kotoba LIEF v1 ELF header binding and assert ident/header fields.
# Must run from within the kotoba directory.
if [ "$(basename "$PWD")" != "kotoba" ]; then
  echo "$0: must be run from within the kotoba directory!"
  exit 1
fi

set -euo pipefail

KOTOBA_BIN="${KOTOBA:-kotoba}"
OUT="${TMPDIR:-/tmp}/lief-kotoba.wasm"

if ! command -v "$KOTOBA_BIN" >/dev/null 2>&1; then
  echo "kotoba CLI is required (kotoba-lang/kotoba v0.7.2)" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node is required to instantiate the wasm module" >&2
  exit 1
fi

if [ ! -f fixtures/tiny64le.elf ]; then
  echo "missing fixtures/tiny64le.elf" >&2
  exit 1
fi

json=$("$KOTOBA_BIN" compile lief.kotoba --target wasm --output "$OUT" --json)
echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
ok = d.get("kotoba.cli/ok?")
code = d.get("kotoba.cli/code")
print("lief.kotoba", ok, code, d.get("kotoba.cli/message") or "")
if not ok or code != "emitted":
    sys.exit(1)
profile = (d.get("kotoba.cli/data") or {}).get("value-profile")
target = ((d.get("kotoba.cli/data") or {}).get("compatibility") or {}).get("target")
print("value-profile", profile, "target", target)
if profile != "i64-v1":
    print("expected value-profile i64-v1", file=sys.stderr)
    sys.exit(1)
'

python3 -c '
import struct, sys
data = open("fixtures/tiny64le.elf", "rb").read()
if len(data) != 64:
    print("fixture length", len(data), "expected 64", file=sys.stderr)
    sys.exit(1)
if data[:4] != b"\x7fELF":
    print("fixture magic is not 7fELF", file=sys.stderr)
    sys.exit(1)
if data[4] != 2 or data[5] != 1:
    print("fixture class/data", data[4], data[5], "expected 2/1", file=sys.stderr)
    sys.exit(1)
e_type, e_machine = struct.unpack_from("<HH", data, 16)
if e_type != 3 or e_machine != 62:
    print("fixture type/machine", e_type, e_machine, "expected 3/62", file=sys.stderr)
    sys.exit(1)
print("fixture tiny64le.elf: ELF64 LSB ET_DYN EM_X86_64")
'

node run_wasm.mjs "$OUT"
