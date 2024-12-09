About
=====

The purpose of this project is to provide a cross platform library that can parse, modify and
abstract ELF, PE and MachO formats.

Main features:

  * **Parsing**: LIEF can parse ELF, PE, MachO, OAT, DEX, VDEX, ART and provides an user-friendly API to access to format internals.
  * **Modify**: LIEF enables to modify some parts of these formats
  * **Abstract**: Three formats have common features like sections, symbols, entry point... LIEF factors them.
  * **API**: LIEF can be used in C, C++, Python and Rust

LIEF Extended:

  * DWARF/PDB Support
  * Objective-C Metadata
  * dyld shared cache

Checkout: https://lief.re/doc/latest/extended/intro.html for the details

Getting Started
================

.. code-block:: console

  $ pip install lief

.. code-block:: python

  import lief

  elf = lief.ELF.parse("/bin/ls")
  for section in elf.sections:
      print(section.name, len(section.content))

  pe = lief.PE.parse("cmd.exe")
  for imp in pe.imports:
      print(imp.name)

  fat = lief.MachO.parse("/bin/dyld")
  for macho in fat:
      for sym in macho.symbols:
          print(sym)

Documentation
=============

* `Main documentation <https://lief.re/doc/latest/index.html>`_
* `API <https://lief.re/doc/latest/api/python/index.html>`_

Contact
=======

* **Mail**: contact at lief.re
* **Discord**: `LIEF <https://discord.gg/jGQtyAYChJ>`_

Authors
=======

Romain Thomas `@rh0main <https://x.com/rh0main>`_

----

LIEF is provided under the `Apache 2.0 license <https://github.com/lief-project/LIEF/blob/0.15.1/LICENSE>`_
