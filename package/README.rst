About
=====

The purpose of this project is to provide a cross platform library that can parse, modify and
abstract ELF, PE and MachO formats.

Main features:

  * **Parsing**: LIEF can parse ELF, PE, MachO, OAT, DEX, VDEX, ART and provides an user-friendly API to access to format internals.
  * **Modify**: LIEF enables to modify some parts of these formats
  * **Abstract**: Three formats have common features like sections, symbols, entry point... LIEF factors them.
  * **API**: LIEF can be used in C, C++ and Python


Downloads / Install
===================

First, make sure to have an updated version of setuptools:

.. code-block:: console

   $ pip install setuptools --upgrade

To install the latest **version** (release):

.. code-block:: console

   $ pip install lief

To install nightly build:

.. code-block:: console

   $ pip install [--user] --index-url https://lief.s3-website.fr-par.scw.cloud/latest lief


Getting started
===============

Python
------

.. code-block:: python

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

C++
---

.. code-block:: cpp

  #include <LIEF/LIEF.hpp>

  int main(int argc, char** argv) {
    // ELF
    try {
      std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse("/bin/ls");
      std::cout << *elf << '\n';
    } catch (const LIEF::exception& err) {
      std::cerr << err.what() << '\n';
    }

    // PE
    try {
      std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("C:\\Windows\\explorer.exe");
      std::cout << *pe << '\n';
    } catch (const LIEF::exception& err) {
      std::cerr << err.what() << '\n';
    }

    // Mach-O
    try {
      std::unique_ptr<LIEF::MachO::FatBinary> macho = LIEF::MachO::Parser::parse("/bin/ls");
      std::cout << *macho << '\n';
    } catch (const LIEF::exception& err) {
      std::cerr << err.what() << '\n';
    }

    return 0;
  }

C (Limited API)
----------------

.. code-block:: cpp

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

Documentation
=============

* `Main documentation <https://lief-project.github.io/doc/latest/index.html>`_
* `Tutorial <https://lief-project.github.io/doc/latest/tutorials/index.html>`_
* `API <https://lief-project.github.io/doc/latest/api/index.html>`_
* `Doxygen <https://lief-project.github.io/doc/latest/doxygen/index.html>`_

Contact
=======

* **Mail**: contact at lief.re
* **Gitter**: `lief-project <https://gitter.im/lief-project>`_


Authors
=======

Romain Thomas `@rh0main <https://twitter.com/rh0main>`_ - `Quarkslab <https://www.quarkslab.com>`_

----

LIEF is provided under the `Apache 2.0 license <https://github.com/lief-project/LIEF/blob/0.12.3/LICENSE>`_
