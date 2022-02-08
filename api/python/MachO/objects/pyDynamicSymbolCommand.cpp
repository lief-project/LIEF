/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DynamicSymbolCommand::*)(void) const;

template<class T>
using setter_t = void (DynamicSymbolCommand::*)(T);

template<class T>
using no_const_getter = T (DynamicSymbolCommand::*)(void);


template<>
void create<DynamicSymbolCommand>(py::module& m) {

  py::class_<DynamicSymbolCommand, LoadCommand>(m, "DynamicSymbolCommand",
      R"delim(
      Class that represents the LC_DYSYMTAB command.
      This command completes the LC_SYMTAB (SymbolCommand) to provide
      a better granularity over the symbols layout.
      )delim")

    .def_property("idx_local_symbol",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::idx_local_symbol),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::idx_local_symbol),
      "Index of the first symbol in the group of local symbols."
    )

    .def_property("nb_local_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_local_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_local_symbols),
      "Number of symbols in the group of local symbols."
    )

    .def_property("idx_external_define_symbol",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::idx_external_define_symbol),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::idx_external_define_symbol),
      "Index of the first symbol in the group of defined external symbols."
    )

    .def_property("nb_external_define_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_define_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_define_symbols),
      "Number of symbols in the group of defined external symbols."
    )

    .def_property("idx_undefined_symbol",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::idx_undefined_symbol),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::idx_undefined_symbol),
      "Index of the first symbol in the group of undefined external symbols."
    )

    .def_property("nb_undefined_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_undefined_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_undefined_symbols),
      "Number of symbols in the group of undefined external symbols."
    )

    .def_property("toc_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::toc_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::toc_offset),
      R"delim(
      Byte offset from the start of the file to the table of contents data.
      Table of content is used by legacy Mach-O loader and this field should be set to 0
      )delim")

    .def_property("nb_toc",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_toc),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_toc),
      R"delim(
      Number of entries in the table of contents
      Should be set to 0 on recent Mach-O
      )delim")

    .def_property("module_table_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::module_table_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::module_table_offset),
      R"delim(
      Byte offset from the start of the file to the module table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim")

    .def_property("nb_module_table",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_module_table),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_module_table),
      R"delim(
      Number of entries in the module table.
      This field seems unused by recent Mach-O loader and should be set to 0.
      )delim")

    .def_property("external_reference_symbol_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::external_reference_symbol_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::external_reference_symbol_offset),
      R"delim(
      Byte offset from the start of the file to the external reference table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim")

    .def_property("nb_external_reference_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_reference_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_reference_symbols),
      R"delim(
      Number of entries in the external reference table.
      This field seems unused by recent Mach-O loader and should be set to 0.
      )delim")

    .def_property("indirect_symbol_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::indirect_symbol_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::indirect_symbol_offset),
      R"delim(
      Byte offset from the start of the file to the indirect symbol table data.

      Indirect symbol table is used by the loader to speed-up symbol resolution during
      the *lazy binding* process

      References:

        * ``dyld-519.2.1/src/ImageLoaderMachOCompressed.cpp``
        * ``dyld-519.2.1/src/ImageLoaderMachOClassic.cpp``
      )delim")

    .def_property("nb_indirect_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_indirect_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_indirect_symbols),
      "Number of entries in the indirect symbol table.")

    .def_property("external_relocation_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::external_relocation_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::external_relocation_offset),
      R"delim(
      Byte offset from the start of the file to the module table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim")

    .def_property("nb_external_relocations",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_relocations),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_relocations),
      R"delim(
      Number of entries in the external relocation table.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim")

    .def_property("local_relocation_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::local_relocation_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::local_relocation_offset),
      R"delim(
      Byte offset from the start of the file to the local relocation table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim")

    .def_property("nb_local_relocations",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_local_relocations),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_local_relocations),
      R"delim(
      Number of entries in the local relocation table.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim")

    .def("__eq__", &DynamicSymbolCommand::operator==)
    .def("__ne__", &DynamicSymbolCommand::operator!=)
    .def("__hash__",
        [] (const DynamicSymbolCommand& cmd) {
          return Hash::hash(cmd);
        })


    .def("__str__",
        [] (const DynamicSymbolCommand& info)
        {
          std::ostringstream stream;
          stream << info;
          return stream.str();
        });

}

}
}
