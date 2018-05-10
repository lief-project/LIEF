Getting started
===============

Python
------

.. code-block:: python

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

  # OAT
  binary = lief.parse("android.odex")
  print(binary)

  # DEX
  dex = lief.DEX.parse("classes.dex")
  print(dex)

  # VDEX
  vdex = lief.VDEX.parse("classes.vdex")
  print(vdex)

  # ART
  art = lief.ART.parse("boot.art")
  print(art)

Python API documentation is available here: :ref:`python-api-ref`

C++
---

.. code-block:: cpp

  #include <LIEF/LIEF.hpp>
  int main(int argc, const char** argv) {
    LIEF::ELF::Binary*   elf   = LIEF::ELF::Parser::parse("/usr/bin/ls");
    LIEF::PE::Binary*    pe    = LIEF::PE::Parser::parse("C:\\Windows\\explorer.exe");
    LIEF::MachO::Binary* macho = LIEF::MachO::Parser::parse("/usr/bin/ls");

    LIEF::OAT::Binary*   oat   = LIEF::OAT::Parser::parse("android.odex");
    LIEF::DEX::File*     dex   = LIEF::DEX::Parser::parse("classes.dex");
    LIEF::OAT::File*     vdex  = LIEF::VDEX::Parser::parse("classes.vdex");
    LIEF::OAT::File*     art   = LIEF::ART::Parser::parse("boot.art");

    std::cout << *elf   << std::endl;
    std::cout << *pe    << std::endl;
    std::cout << *macho << std::endl;

    std::cout << *oat << std::endl;
    std::cout << *dex << std::endl;
    std::cout << *vdex << std::endl;
    std::cout << *art << std::endl;

    delete elf;
    delete pe;
    delete macho;
    delete oat;
    delete dex;
    delete vdex;
    delete art;
  }


C++ API documentation is available here: :ref:`cpp-api-ref`

C
--

.. code-block:: c

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


C API documentation is available here: :ref:`c-api-ref`


















