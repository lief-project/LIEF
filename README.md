<p align="center" >
<img width="90%" src="https://github.com/lief-project/LIEF/blob/main/.github/images/architecture.png"/><br />
</p>

<p align="center">
  <a href="https://discord.gg/jGQtyAYChJ">
    <img src="https://img.shields.io/discord/1117013848914931762">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/actions/workflows/linux-x86-64.yml">
    <img alt="Linux x86-64 CI status" src="https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/linux-x86-64.yml?branch=main&label=Linux%20x86-64&logo=github">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/actions/workflows/linux-aarch64.yml">
    <img alt="Linux AArch64 CI status" src="https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/linux-aarch64.yml?branch=main&label=Linux%20AArch64&logo=github">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/actions/workflows/android.yml">
    <img alt="Android CI status" src="https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/android.yml?branch=main&label=Android&logo=github">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/actions/workflows/osx.yml">
    <img alt="macOS CI status" src="https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/osx.yml?branch=main&label=macOS&logo=github">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/actions/workflows/ios.yml">
    <img alt="iOS CI status" src="https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/ios.yml?branch=main&label=iOS&logo=github">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/actions/workflows/windows-all.yml">
    <img alt="Windows CI status" src="https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/windows-all.yml?branch=main&label=Windows&logo=github">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/releases">
    <img src="https://img.shields.io/github/v/release/lief-project/LIEF?style=flat-square">
  </a>
  &nbsp;
  <a href="https://twitter.com/LIEF_project">
   <img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/lief_project">
  </a>
  &nbsp;
  <a href="https://gurubase.io/g/lief">
    <img src="https://img.shields.io/badge/Gurubase-Ask%20LIEF%20Guru-006BFF">
  </a>
</p>

<br />
<p align="center">
  <a href="https://lief.re/blog/"><b>Blog</b></a> •
  <a href="https://lief.re/doc/latest/index.html"><b>Documentation</b></a> •
  <a href="#user-content-about-1"><b>About</b></a>
</p>
<br />

# About

The purpose of this project is to provide a cross-platform library to parse,
modify and abstract ELF, PE and MachO formats.

**Main features**:

  * **Parsing**: LIEF can parse ELF, PE, MachO, OAT, DEX, VDEX, ART and provides an user-friendly API to access to internals.
  * **Modify**: LIEF can use to modify some parts of these formats (adding a section, changing a symbol's name, ...)
  * **Abstract**: Three formats have common features like sections, symbols, entry point... LIEF factors them.
  * **API**: LIEF can be used in C++, Python, Rust and C

**Extended features**:

  * [**DWARF/PDB** Support](https://lief.re/doc/latest/extended/debug_info/index.html)
  * [**Objective-C** Metadata](https://lief.re/doc/latest/extended/objc/index.html)
  * [**Dyld Shared Cache**](https://lief.re/doc/latest/extended/dsc/index.html) with support for extracting Dylib
  * [**Disassembler**](https://lief.re/doc/latest/extended/disassembler/index.html): AArch64, x86/x86-64, ARM, RISC-V, Mips, PowerPC, eBPF
  * [**Assembler**](https://lief.re/doc/latest/extended/assembler/index.html): AArch64, x86/x86-64


# Content

- [About](#about)
- [Download / Install](#downloads--install)
- [Getting started](#getting-started)
- [Documentation](#documentation)
  - [Rust](https://lief.re/doc/stable/rust/lief/)
  - [Sphinx](https://lief.re/doc/latest/index.html)
  - [Doxygen](https://lief.re/doc/latest/doxygen/index.html)
  - Tutorials:
    - [Parse and manipulate formats](https://lief.re/doc/latest/tutorials/01_play_with_formats.html)
    - [Create a PE from scratch](https://lief.re/doc/latest/tutorials/02_pe_from_scratch.html)
    - [Play with ELF symbols](https://lief.re/doc/latest/tutorials/03_elf_change_symbols.html)
    - [ELF Hooking](https://lief.re/doc/latest/tutorials/04_elf_hooking.html)
    - [Infecting the plt/got](https://lief.re/doc/latest/tutorials/05_elf_infect_plt_got.html)
    - [PE Hooking](https://lief.re/doc/latest/tutorials/06_pe_hooking.html)
    - [PE Resources](https://lief.re/doc/latest/tutorials/07_pe_resource.html)
    - [Transforming an ELF executable into a library](https://lief.re/doc/latest/tutorials/08_elf_bin2lib.html)
    - [How to use frida on a non-rooted device](https://lief.re/doc/latest/tutorials/09_frida_lief.html)
    - [Android formats](https://lief.re/doc/latest/tutorials/10_android_formats.html)
    - [Mach-O modification](https://lief.re/doc/latest/tutorials/11_macho_modification.html)
    - [ELF Coredump](https://lief.re/doc/latest/tutorials/12_elf_coredump.html)
    - [PE Authenticode](https://lief.re/doc/latest/tutorials/13_pe_authenticode.html)
- [Contact](#contact)
- [About](#about)
  - [Authors](#authors)
  - [License](#license)
  - [Bibtex](#bibtex)

## Downloads / Install

## C++

```cmake
find_package(LIEF REQUIRED)
target_link_libraries(my-project LIEF::LIEF)
```

## Rust

```toml
[package]
name    = "my-awesome-project"
version = "0.0.1"
edition = "2021"

[dependencies]
lief = "0.16.6"
```

## Python

To install the latest **version** (release):

```console
pip install lief
```

To install nightly build:

```console
pip install [--user] --force-reinstall --index-url https://lief.s3-website.fr-par.scw.cloud/latest lief==0.17.0.dev0
```

### Packages

- LIEF Extended: https://extended.lief.re (GitHub OAuth)
- **Nightly**:
  * SDK: https://lief.s3-website.fr-par.scw.cloud/latest/sdk
  * Python Wheels: https://lief.s3-website.fr-par.scw.cloud/latest/lief
- **v0.16.6**: https://github.com/lief-project/LIEF/releases/tag/0.16.6

Here are guides to install or integrate LIEF:

  * [Python](https://lief.re/doc/latest/installation.html#python)
  * [Visual Studio](https://lief.re/doc/latest/installation.html#visual-studio-integration)
  * [XCode](https://lief.re/doc/latest/installation.html#xcode-integration)
  * [CMake](https://lief.re/doc/latest/installation.html#cmake-integration)

## Getting started

### Python

```python
import lief

# ELF
binary = lief.parse("/usr/bin/ls")
for section in binary.sections:
    print(section.name, section.virtual_address)

# PE
binary = lief.parse("C:\\Windows\\explorer.exe")

if rheader := pe.rich_header:
    print(rheader.key)

# Mach-O
binary = lief.parse("/usr/bin/ls")
for fixup in binary.dyld_chained_fixups:
    print(fixup)
```

### Rust

```rust
use lief::Binary;
use lief::pe::debug::Entries::CodeViewPDB;

if let Some(Binary::PE(pe)) = Binary::parse(path.as_str()) {
    for entry in pe.debug() {
        if let CodeViewPDB(pdb_view) = entry {
            println!("{}", pdb_view.filename());
        }
    }
}
```

### C++

```cpp
#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
  // ELF
  if (std::unique_ptr<const LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse("/bin/ls")) {
    for (const LIEF::ELF::Section& section : elf->sections()) {
      std::cout << section->name() << ' ' << section->virtual_address() << '\n';
    }
  }

  // PE
  if (std::unique_ptr<const LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("C:\\Windows\\explorer.exe")) {
    if (const LIEF::PE::RichHeader* rheader : pe->rich_header()) {
      std::cout << rheader->key() << '\n';
    }
  }

  // Mach-O
  if (std::unique_ptr<LIEF::MachO::FatBinary> macho = LIEF::MachO::Parser::parse("/bin/ls")) {
    for (const LIEF::MachO::DyldChainedFixups& fixup : macho->dyld_chained_fixups()) {
      std::cout << fixup << '\n';
    }
  }

  return 0;
}

```

### C (Limited API)

```cpp
#include <LIEF/LIEF.h>

int main(int argc, char** argv) {
  Elf_Binary_t* elf = elf_parse("/usr/bin/ls");

  Elf_Section_t** sections = elf->sections;

  for (size_t i = 0; sections[i] != NULL; ++i) {
    printf("%s\n", sections[i]->name);
  }

  elf_binary_destroy(elf);
  return 0;
}
```

## Documentation

* [Main documentation](https://lief.re/doc/latest/index.html)
* [Doxygen](https://lief.re/doc/latest/doxygen/index.html)
* [Rust](https://lief.re/doc/stable/rust/lief/)

## Contact

* **Mail**: contact at lief re
* **Discord**: [LIEF](https://discord.gg/7hRFGWYedu)

## About

### Authors

Romain Thomas ([@rh0main](https://www.romainthomas.fr/)) - [Quarkslab](https://www.quarkslab.com)

### License

LIEF is provided under the [Apache 2.0 license](https://github.com/lief-project/LIEF/blob/0.16.6/LICENSE).

### Bibtex

```bibtex
@MISC {LIEF,
  author       = "Romain Thomas",
  title        = "LIEF - Library to Instrument Executable Formats",
  howpublished = "https://lief.quarkslab.com/",
  month        = "apr",
  year         = "2017"
}
```


