# LIEF Kotoba binding (v1)

Honest v1 surface for [LIEF](https://github.com/lief-project/LIEF) on this
fork (`kotoba-lang/LIEF`). It sits next to `api/python` and `api/rust` as a
language tree. It is **not** a wrap of the C++ library: Kotoba has no ambient
FFI, so this module reads packed header bytes in-language.

This is **not** a replacement for LIEF C++ / Python / Rust. It is **not**
robotics-ready. It does **not** parse PE, Mach-O, COFF, relocations, sections,
or segments.

## v1 scope

Supported:

- ELF identification (`e_ident[16]`, including magic `0x7F ELF`)
- `EI_CLASS` (ELF32 / ELF64)
- `EI_DATA` (LSB / MSB)
- `e_type` and `e_machine` at offsets `+0x10` / `+0x12` (same on
  `Elf32_Ehdr` and `Elf64_Ehdr` in `src/ELF/structures.inc`)
- One vendored fixture: `fixtures/tiny64le.elf` (64-byte ELF64 LSB x86-64
  `ET_DYN` header, no program or section table)

Not in v1: PE, Mach-O, program headers, section headers, symbols, relocations,
notes, or any write/modify path.

## Kotoba surface

Verified on [kotoba-lang/kotoba](https://github.com/kotoba-lang/kotoba)
**v0.7.2**. Language authority:
[kotoba-lang/kotoba-lang](https://github.com/kotoba-lang/kotoba-lang).

Admitted pieces this library uses:

- typed `ns` / `defn`, `i64` only
- `+`, `-`, `*`, `quot`, `<`, `>=`, `=`, `and`, `if`, `let`

Constraints this binding does not paper over:

- The wasm32 value profile is `i64-v1`. There is no IEEE float and no
  nonempty `bytes` builtin.
- Wire prefixes are packed as little-endian i64 words (8 file bytes per
  word). Callers that have a host buffer pack `w0`/`w1`/`w2` themselves.
- `require` is unused; `lief.kotoba` is one compilation unit.
- `kotoba compile --target wasm` must emit a module with no host imports.

## Public API

| Function | Arguments | Result |
| --- | --- | --- |
| `ident-magic-ok` | `w0` | `1` if bytes 0–3 are `7F 45 4C 46` |
| `ident-class` | `w0` | `EI_CLASS` (`1` ELF32, `2` ELF64) |
| `ident-data` | `w0` | `EI_DATA` (`1` LSB, `2` MSB) |
| `ident-version` | `w0` | `EI_VERSION` |
| `ident-byte` | `w0`, `w1`, `i` | `e_ident[i]` for `i` in `0..15` |
| `file-type` | `w0`, `w2` | `e_type` (endian from `EI_DATA`) |
| `machine-type` | `w0`, `w2` | `e_machine` (endian from `EI_DATA`) |
| `main` | (none) | `0` if vendored fixture asserts pass |

Field values match `LIEF::ELF::Header` (`CLASS`, `ELF_DATA`, `FILE_TYPE`)
and `LIEF::ELF::ARCH`.

## Testing

From this directory, with kotoba CLI v0.7.2 and Node.js on `PATH`:

```
bash checks.sh
```

`checks.sh` compiles `lief.kotoba` to wasm32, requires `kotoba.cli/ok?` and
`emitted`, checks wasm magic and `i64-v1`, independently reads the ELF
fixture, then instantiates the module (no imports) and asserts ident/header
fields. It does not invent a pass.

Fork CI for this tree is `.github/workflows/kotoba.yml` (`kotoba/**` and
that workflow file). Native LIEF workflows path-ignore `kotoba/**` and
`.github/workflows/kotoba*.yml`.

Install the CLI from the v0.7.2 release tarball or
`brew tap kotoba-lang/kotoba && brew install kotoba`.

## Compile

```
kotoba compile lief.kotoba --target wasm --output lief.wasm --json
```

Accept `kotoba.cli/ok?` true and `kotoba.cli/code` `emitted`.

## License

Apache-2.0, same as the rest of this repository.
