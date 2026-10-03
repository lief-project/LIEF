(tools-lief-dwarfdump)=

# {fa}`solid fa-bars-staggered` lief-dwarfdump

`lief-dwarfdump` reconstructs C/C++ declarations from the DWARF debug
information of a binary. It is a Rust command-line front end for the
{ref}`declaration <extended-dwarf-to-decl>` API.

:::{admonition} LIEF Extended
:class: warning

DWARF support is an {ref}`extended <extended-intro>` feature.
:::

## Usage

The tool takes the binary or the DWARF file to read, and generates the C/C++
declaration.

### Complete Dump

Without any options, `lief-dwarfdump` prints every compilation unit:

```bash
$ lief-dwarfdump liblinker
/*
 * Producer: Binary Ninja DWARF Export Plugin
 */

/*
 * Addr: 0x0000
 * size: 0x0040
 */
static Elf64_Header __elf_header;

[...]

/*
 * Address: 0xec50
 */
void _exit(int status);
```

By default, only functions and variables are rendered. `--show-types` can be
used to emit the definition of the types they reference:

```bash
$ lief-dwarfdump --show-types liblinker
```

### By Address

`--address` selects a single function by its virtual address, along with its
stack variables.

```bash
$ lief-dwarfdump --address 0x1ed4 libdexprotector.so.dwarf
/*
 * Address: 0x1ed4
 */
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    /* Start: 0x001eec */ {
        /* Start: 0x001ef8 */ {
          Call the JNI_OnLoad from the payload loaded by the first DT_INIT_ARRAY constructor
        } /* End: 0x001efc */
    } /* End: 0x001f10 */
}
```

### By Name

`--function` selects a single function by its (demangled) name:

```bash
$ lief-dwarfdump --function dp_mmap_payload libdexprotector.so.dwarf
/*
 * Address: 0x0c44
 */
bool dp_mmap_payload(void *start, unsigned long long size, mmap_info_t *info) {
    /*
     * Stack addr: -0x00f8
     * size: 0x0038
     */
    cipher_context_t cipher_ctx;
    [...]
}
```

### By Type

`--type` selects a single type by its short name:

```bash
$ lief-dwarfdump --type key_t libdexprotector.so.dwarf
unsigned char[32]
```

## Compilation

`lief-dwarfdump` links against the {ref}`Extended Rust SDK <extended-intro>`.
Set {ref}`LIEF_RUST_PRECOMPILED <lief-rust-precompiled>` at the extracted SDK,
then build the tool with `cargo` from the `tools/lief-dwarfdump` directory:

```bash
$ export LIEF_RUST_PRECOMPILED=$(pwd)/LIEF-extended-rust-0.16.0.2378-Linux-x86_64
$ cargo build [--release]
$ ./target/{release,debug}/lief-dwarfdump --version
```

## Man Page

Given the `lief-dwarfdump` binary, you can generate a man page using the
following command:

```bash
$ lief-dwarfdump --generate-manpage ./lief-dwarfdump.1
```

This functionality is provided by [clap_mangen](https://crates.io/crates/clap_mangen).

## Shell Completion

Thanks to [clap](https://github.com/clap-rs/clap) and its `clap_complete`
extension, you can generate auto-completion for various shells:

```bash
$ ./lief-dwarfdump --generate {bash, elvish, fish, powershell, zsh}
```
