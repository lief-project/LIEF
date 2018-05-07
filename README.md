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
    <img src="https://img.shields.io/badge/release-0.8.3-brightgreen.svg?style=default">
  </a>
</p>

# About 

The purpose of this project is to provide a cross platform library which can parse, modify and abstract ELF, PE and MachO formats.

Main features:

  * **Parsing**: LIEF can parse ELF, PE, MachO and provides an user-friendly API to access to format internals.
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
- [Contact](#contact)
- [Authors](#authors)

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
pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.8.3.dev.zip
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
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.3-Linux.tar.gz">SDK</a></td>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.3-win32.zip">SDK</a></td>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.3-win64.zip">SDK</a></td>
  <td><a href="https://github.com/lief-project/packages/raw/lief-master-latest/LIEF-0.8.3-Darwin.tar.gz">SDK</a></td>
</tr>

<tr>
  <td colspan="4"><p align="center"><a href="https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.8.3.dev.zip">Python</a></p></td>
</tr>
</table>

<table>
<tr><td colspan="6"><b><img src="https://img.shields.io/badge/release-0.8.3-brightgreen.svg?style=default"></b></td></tr>
<tr>
    <th>Linux</th>
    <th>Windows</th>
    <th>OSX</th>
    <th>CentOS</th>
    <th>Android</th>
  <th>Documentation</th>
</tr>

<tr>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-Linux.tar.gz">SDK</a></td>
  <td>
    <a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-win32.zip">SDK - x86</a>
    <br />
    <a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-win64.zip">SDK - x86-64</a>
  </td>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-Darwin.tar.gz">SDK</a></td>
  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-CentOS.tar.gz">SDK</a></td>

  <td>
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-Android_x86_64.tar.gz">SDK - x86-64</a>
  <br />
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-Android_x86.tar.gz">SDK - x86</a>
  <br />
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-Android_armeabi-v7a.tar.gz">SDK - ARM</a>
  <br />
  <a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/LIEF-0.8.3-Android_aarch64.tar.gz">SDK - AARCH64</a>
  </td>

  <td><a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/documentation-0.8.3.tar.gz">Sphinx + Doxygen</a></td>
</tr>


<tr>
  <td colspan="3"><p align="center"><a href="https://github.com/lief-project/LIEF/releases/download/0.8.3/pylief-0.8.3.zip">Python</a></p></td>
</tr>


</table>


Here one can find guides to install or integrate LIEF:

  * [Python](https://lief.quarkslab.com/doc/installation.html#python)
  * [VisualStudio](https://lief.quarkslab.com/doc/installation.html#visual-studio-integration)
  * [XCode](https://lief.quarkslab.com/doc/installation.html#xcode-integration)
  * [CMake](https://lief.quarkslab.com/doc/installation.html#cmake-integration)

## Getting started

### Python

<p align="center" >
<img width="100%" src="https://github.com/lief-project/LIEF/blob/master/.github/images/pythonapi.png"/><br />
</p>

### C++

<p align="center" >
<img width="100%" src="https://github.com/lief-project/LIEF/blob/master/.github/images/cpp.png"/><br />
</p>

### C

<p align="center" >
<img width="100%" src="https://github.com/lief-project/LIEF/blob/master/.github/images/capi.png"/><br />
</p>

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

