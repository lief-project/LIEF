<p align="center" >
<img width="40%" src="http://romainthomas.fr/logo_blue_with_name_500.png"/><br />
</p>
<hr>
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
    <img src="https://img.shields.io/badge/release-0.8.0-brightgreen.svg?style=default">
  </a>
</p>

The purpose of this project is to provide a cross platform library which can parse, modify and abstract ELF, PE and MachO formats.

Main features:

  * **Parsing**: LIEF can parse ELF, PE, MachO and provides an user-friendly API to access to format internals.
  * **Modify**: LIEF enables to modify some parts of these formats
  * **Abstract**: Three formats have common features like sections, symbols, entry point... LIEF factors them.
  * **API**: LIEF can be used in C, C++ and Python


## Downloads / Install

First:

```bash
pip install setuptools --upgrade
```

To install the latest **version**:

```python
pip install lief
```

To install the latest **commit**:

```python
pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.8.0.dev.zip
```
### Packages

<table>
<tr><td colspan="4"><img src="https://img.shields.io/badge/release-master-brightgreen.svg?style=default"></td></tr>
<tr>
    <th>Linux</th>
    <th>Windows - x86</th>
    <th>Windows - x86-64</th>
    <th>OSX</th>
</tr>

<tr>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.0-Linux.tar.gz">SDK</a></td>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.0-win32.zip">SDK</a></td>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.0-win64.zip">SDK</a></td>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.0-Darwin.tar.gz">SDK</a></td>
</tr>

<tr>
  <td colspan="4"><p align="center"><a href="https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.8.0.dev.zip">Python</a></p></td>
</tr>
</table>

<table>
<tr><td colspan="6"><b><img src="https://img.shields.io/badge/release-0.8.0-brightgreen.svg?style=default"></b></td></tr>
<tr>
    <th>Linux</th>
    <th>Windows</th>
    <th>OSX</th>
    <th>CentOS</th>
    <th>Android</th>
  <th>Documentation</th>
</tr>

<tr>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-Linux.tar.gz">SDK</a></td>
  <td>
    <a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-win32.zip">SDK - x86</a>
    <br />
    <a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-win64.zip">SDK - x86-64</a>
  </td>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-Darwin.tar.gz">SDK</a></td>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-CentOS.tar.gz">SDK</a></td>
  
  <td>
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-Android_x86_64.tar.gz">SDK - x86-64</a>
  <br />
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-Android_x86.tar.gz">SDK - x86</a>
  <br />
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-Android_armeabi-v7a.tar.gz">SDK - ARM</a>
  <br />
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/LIEF-0.8.0-Android_aarch64.tar.gz">SDK - AARCH64</a>
  </td>
  
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/documentation-0.8.0.tar.gz">Sphinx + Doxygen</a></td>
</tr>


<tr>
  <td colspan="3"><p align="center"><a href="https://github.com/lief-project/LIEF/releases/download/0.8.0/pylief-0.8.0.zip">Python</a></p></td>
</tr>


</table>


Here one can find guides to install or integrate LIEF:

  * [Python](https://lief.quarkslab.com/doc/installation.html#python)
  * [VisualStudio](https://lief.quarkslab.com/doc/installation.html#visual-studio-integration)
  * [XCode](https://lief.quarkslab.com/doc/installation.html#xcode-integration)
  * [CMake](https://lief.quarkslab.com/doc/installation.html#cmake-integration)

## Getting started

### Python

```python
import lief
# ELF
binary = lief.parse("/usr/bin/ls")
print(binary)

# PE
binary = lief.parse("C:\\Windows\\explorer.exe")
print(binary)

# Mach-O
binary = lief.parse("/usr/bin/ls")
print(binary)

```

### C++

```cpp
#include <LIEF/LIEF.hpp>
int main(int argc, const char** argv) {
  LIEF::ELF::Binary*   elf   = LIEF::ELF::Parser::parse("/usr/bin/ls");
  LIEF::PE::Binary*    pe    = LIEF::PE::Parser::parse("C:\\Windows\\explorer.exe");
  LIEF::MachO::Binary* macho = LIEF::MachO::Parser::parse("/usr/bin/ls");

  std::cout << *elf   << std::endl;
  std::cout << *pe    << std::endl;
  std::cout << *macho << std::endl;

  delete elf;
  delete pe;
  delete macho;
}
```

### C

```cpp
#include <LIEF/LIEF.h>
int main(int argc, const char** argv) {

  Elf_Binary_t*    elf_binary     = elf_parse("/usr/bin/ls");
  Pe_Binary_t*     pe_binary      = pe_parse("C:\\Windows\\explorer.exe");
  Macho_Binary_t** macho_binaries = macho_parse("/usr/bin/ls");

  Pe_Section_t**    pe_sections    = pe_binary->sections;
  Elf_Section_t**   elf_sections   = elf_binary->sections;
  Macho_Section_t** macho_sections = macho_binaries[0]->sections;

  for (size_t i = 0; pe_sections[i] != NULL; ++i) {
    printf("%s\n", pe_sections[i]->name)
  }

  for (size_t i = 0; elf_sections[i] != NULL; ++i) {
    printf("%s\n", elf_sections[i]->name)
  }

  for (size_t i = 0; macho_sections[i] != NULL; ++i) {
    printf("%s\n", macho_sections[i]->name)
  }

  elf_binary_destroy(elf_binary);
  pe_binary_destroy(pe_binary);
  macho_binaries_destroy(macho_binaries);
}

```
## Documentation

* [Main documentation](http://lief.quarkslab.com/doc/index.html)
* [Tutorial](http://lief.quarkslab.com/doc/tutorials/index.html)
* [API](http://lief.quarkslab.com/doc/api/index.html)
* [Doxygen](http://lief.quarkslab.com/doxygen/index.html)

## Contact

* **Mail**: lief at quarkslab com
* **Gitter**: [lief-project](https://gitter.im/lief-project)

## Authors

Romain Thomas ([@rh0main](https://twitter.com/rh0main)) - [Quarkslab](https://www.quarkslab.com)

---------------

<p align="center" >
<img width="40%" src="http://lief.quarkslab.com/resources/QB-big.png"/>
</p>

