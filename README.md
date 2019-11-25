<p align="center" >
<img width="90%" src="https://github.com/lief-project/LIEF/blob/master/.github/images/architecture.png"/><br />
</p>

<p align="center">
  <a href="https://gitter.im/lief-project">
    <img src="https://img.shields.io/gitter/room/gitterHQ/gitter.svg">
  </a>
  &nbsp;
  <a href="https://travis-ci.org/lief-project/LIEF">
    <img src="https://travis-ci.org/lief-project/LIEF.svg?branch=master">
  </a>
  &nbsp;
  <a href="https://circleci.com/gh/lief-project/LIEF/tree/master">
    <img src="https://circleci.com/gh/lief-project/LIEF/tree/master.svg?style=svg">
  </a>
  &nbsp;
  <a href="https://ci.appveyor.com/project/Romain/lief/branch/master">
    <img src="https://ci.appveyor.com/api/projects/status/0ijlcujac5vh8cas/branch/master?svg=true">
  </a>
  &nbsp;
  <a href="https://github.com/lief-project/LIEF/releases">
    <img src="https://img.shields.io/badge/release-0.10.0-brightgreen.svg?style=default">
  </a>
</p>

# About

The purpose of this project is to provide a cross platform library which can parse, modify and abstract ELF, PE and MachO formats.

Main features:

  * **Parsing**: LIEF can parse ELF, PE, MachO, OAT, DEX, VDEX, ART and provides an user-friendly API to access to format internals.
  * **Modify**: LIEF enables to modify some parts of these formats
  * **Abstract**: Three formats have common features like sections, symbols, entry point... LIEF factors them.
  * **API**: LIEF can be used in C, C++ and Python

# Content

- [About](#about)
- [Download / Install](#downloads--install)
- [Getting started](#getting-started)
- [Documentation](#documentation)
  - [Sphinx](https://lief.quarkslab.com/doc/stable/index.html)
  - [Doxygen](https://lief.quarkslab.com/doc/latest/doxygen/index.html)
  - Tutorials:
    - [Parse and manipulate formats](https://lief.quarkslab.com/doc/latest/tutorials/01_play_with_formats.html)
    - [Create a PE from scratch](https://lief.quarkslab.com/doc/latest/tutorials/02_pe_from_scratch.html)
    - [Play with ELF symbols](https://lief.quarkslab.com/doc/latest/tutorials/03_elf_change_symbols.html)
    - [ELF Hooking](https://lief.quarkslab.com/doc/latest/tutorials/04_elf_hooking.html)
    - [Infecting the plt/got](https://lief.quarkslab.com/doc/latest/tutorials/05_elf_infect_plt_got.html)
    - [PE Hooking](https://lief.quarkslab.com/doc/latest/tutorials/06_pe_hooking.html)
    - [PE Resources](https://lief.quarkslab.com/doc/latest/tutorials/07_pe_resource.html)
    - [Transforming an ELF executable into a library](https://lief.quarkslab.com/doc/latest/tutorials/08_elf_bin2lib.html)
    - [How to use frida on a non-rooted device](https://lief.quarkslab.com/doc/latest/tutorials/09_frida_lief.html)
    - [Android formats](https://lief.quarkslab.com/doc/latest/tutorials/10_android_formats.html)
    - [Mach-O modification](https://lief.quarkslab.com/doc/latest/tutorials/11_macho_modification.html)
    - [ELF Coredump](https://lief.quarkslab.com/doc/latest/tutorials/12_elf_coredump.html)
- [Contact](#contact)
- [About](#about)
  - [Authors](#authors)
  - [License](#license)
  - [Bibtex](#bibtex)

## Downloads / Install

First, make sure to have an updated version of setuptools:

```console
pip install setuptools --upgrade
```

To install the latest **version** (release):

```console
pip install lief
```

To install nightlty build:

```console
pip install [--user] --index-url  https://lief-project.github.io/packages lief
```

### Packages

<table>
<tr><td colspan="4"><a href="https://lief-project.github.io/packages/sdk"><img src="https://img.shields.io/badge/release-master-brightgreen.svg?style=default"></a></td></tr>
<tr>
    <th>Linux</th>
    <th>Windows - x86</th>
    <th>Windows - x86-64</th>
    <th>OSX</th>
</tr>

<tr>
  <td><a href="https://lief-project.github.io/packages/sdk/LIEF-0.11.0-Linux.tar.gz">SDK</a></td>
  <td><a href="https://lief-project.github.io/packages/sdk/LIEF-0.11.0-win32.zip">SDK</a></td>
  <td><a href="https://lief-project.github.io/packages/sdk/LIEF-0.11.0-win64.zip">SDK</a></td>
  <td><a href="https://lief-project.github.io/packages/sdk/LIEF-0.11.0-Darwin.tar.gz">SDK</a></td>
</tr>

<tr>
  <td colspan="4"><p align="center"><a href="https://lief-project.github.io/packages/lief">Python</a></p></td>
</tr>
</table>

<table>
<tr><td colspan="6"><b><img src="https://img.shields.io/badge/release-0.10.0-brightgreen.svg?style=default"></b></td></tr>
<tr>
    <th>Linux</th>
    <th>Windows</th>
    <th>OSX</th>
    <th>Documentation</th>
</tr>

<tr>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.10.0/LIEF-0.10.0-Linux.tar.gz">SDK</a></td>
  <td>
    <a href="https://github.com/lief-project/LIEF/releases/download/0.10.0/LIEF-0.10.0-win32.zip">SDK - x86</a>
    <br />
    <a href="https://github.com/lief-project/LIEF/releases/download/0.10.0/LIEF-0.10.0-win64.zip">SDK - x86-64</a>
  </td>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.10.0/LIEF-0.10.0-Darwin.tar.gz">SDK</a></td>

  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.10.0/documentation-0.10.0.tar.gz">Sphinx + Doxygen</a></td>
</tr>


<tr>
  <td colspan="3"><p align="center"><a href="https://github.com/lief-project/LIEF/releases/download/0.10.0/">Python</a></p></td>
</tr>


</table>

Here are guides to install or integrate LIEF:

  * [Python](https://lief.quarkslab.com/doc/latest/installation.html#python)
  * [VisualStudio](https://lief.quarkslab.com/doc/latest/installation.html#visual-studio-integration)
  * [XCode](https://lief.quarkslab.com/doc/latest/installation.html#xcode-integration)
  * [CMake](https://lief.quarkslab.com/doc/latest/installation.html#cmake-integration)

## Getting started

### Python

```python
import lief

# ELF
binary = lief.parse("/usr/bin/ls")
print(binary)

# PE
binary = lief.parse("C:\\Windows\\explorer.exe")
print(binary)

# Mach-O
binary = lief.parse("/usr/bin/ls")
print(binary)
```

### C++

```cpp
#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
  std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse("/usr/bin/ls");
  std::cout << *elf << std::endl;

  std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("C:\\Windows\\explorer.exe");
  std::cout << *pe << std::endl;

  std::unique_ptr<LIEF::MachO::Binary> macho = LIEF::MachO::Parser::parse("/usr/bin/ls");
  std::cout << *macho << std::endl;
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

* [Main documentation](https://lief.quarkslab.com/doc/latest/index.html)
* [Tutorial](https://lief.quarkslab.com/doc/latest/tutorials/index.html)
* [API](https://lief.quarkslab.com/doc/latest/api/index.html)
* [Doxygen](https://lief.quarkslab.com/doc/latest/doxygen/index.html)

## Contact

* **Mail**: lief at quarkslab com
* **Gitter**: [lief-project](https://gitter.im/lief-project)

## About

### Authors

Romain Thomas ([@rh0main](https://twitter.com/rh0main)) - [Quarkslab](https://www.quarkslab.com)

### License

LIEF is provided under the [Apache 2.0 license](https://github.com/lief-project/LIEF/blob/0.10.0/LICENSE).

### Bibtex

```latex
@MISC {LIEF,
  author       = "Romain Thomas",
  title        = "LIEF - Library to Instrument Executable Formats",
  howpublished = "https://lief.quarkslab.com/",
  month        = "April",
  year         = "2017",
}

```

---------------

<p align="center" >
<img width="40%" src="http://lief.quarkslab.com/resources/QB-big.png"/>
</p>

