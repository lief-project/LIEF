/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/MachO/DynamicSymbolCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<DynamicSymbolCommand>(nb::module_& m) {
  nb::class_<DynamicSymbolCommand, LoadCommand>(m, "DynamicSymbolCommand",
      R"delim(
      Class that represents the LC_DYSYMTAB command.
      This command completes the LC_SYMTAB (SymbolCommand) to provide
      a better granularity over the symbols layout.
      )delim"_doc)

    .def_prop_rw("idx_local_symbol",
      nb::overload_cast<>(&DynamicSymbolCommand::idx_local_symbol, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::idx_local_symbol),
      "Index of the first symbol in the group of local symbols."_doc
    )

    .def_prop_rw("nb_local_symbols",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_local_symbols, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_local_symbols),
      "Number of symbols in the group of local symbols."_doc
    )

    .def_prop_rw("idx_external_define_symbol",
      nb::overload_cast<>(&DynamicSymbolCommand::idx_external_define_symbol, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::idx_external_define_symbol),
      "Index of the first symbol in the group of defined external symbols."_doc
    )

    .def_prop_rw("nb_external_define_symbols",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_external_define_symbols, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_external_define_symbols),
      "Number of symbols in the group of defined external symbols."_doc
    )

    .def_prop_rw("idx_undefined_symbol",
      nb::overload_cast<>(&DynamicSymbolCommand::idx_undefined_symbol, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::idx_undefined_symbol),
      "Index of the first symbol in the group of undefined external symbols."_doc
    )

    .def_prop_rw("nb_undefined_symbols",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_undefined_symbols, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_undefined_symbols),
      "Number of symbols in the group of undefined external symbols."_doc
    )

    .def_prop_rw("toc_offset",
      nb::overload_cast<>(&DynamicSymbolCommand::toc_offset, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::toc_offset),
      R"delim(
      Byte offset from the start of the file to the table of contents data.
      Table of content is used by legacy Mach-O loader and this field should be set to 0
      )delim"_doc)

    .def_prop_rw("nb_toc",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_toc, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_toc),
      R"delim(
      Number of entries in the table of contents
      Should be set to 0 on recent Mach-O
      )delim"_doc)

    .def_prop_rw("module_table_offset",
      nb::overload_cast<>(&DynamicSymbolCommand::module_table_offset, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::module_table_offset),
      R"delim(
      Byte offset from the start of the file to the module table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim"_doc)

    .def_prop_rw("nb_module_table",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_module_table, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_module_table),
      R"delim(
      Number of entries in the module table.
      This field seems unused by recent Mach-O loader and should be set to 0.
      )delim"_doc)

    .def_prop_rw("external_reference_symbol_offset",
      nb::overload_cast<>(&DynamicSymbolCommand::external_reference_symbol_offset, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::external_reference_symbol_offset),
      R"delim(
      Byte offset from the start of the file to the external reference table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim"_doc)

    .def_prop_rw("nb_external_reference_symbols",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_external_reference_symbols, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_external_reference_symbols),
      R"delim(
      Number of entries in the external reference table.
      This field seems unused by recent Mach-O loader and should be set to 0.
      )delim"_doc)

    .def_prop_rw("indirect_symbol_offset",
      nb::overload_cast<>(&DynamicSymbolCommand::indirect_symbol_offset, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::indirect_symbol_offset),
      R"delim(
      Byte offset from the start of the file to the indirect symbol table data.

      Indirect symbol table is used by the loader to speed-up symbol resolution during
      the *lazy binding* process

      References:

        * ``dyld-519.2.1/src/ImageLoaderMachOCompressed.cpp``
        * ``dyld-519.2.1/src/ImageLoaderMachOClassic.cpp``
      )delim"_doc)

    .def_prop_rw("nb_indirect_symbols",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_indirect_symbols, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_indirect_symbols),
      "Number of entries in the indirect symbol table."_doc)

    .def_prop_rw("external_relocation_offset",
      nb::overload_cast<>(&DynamicSymbolCommand::external_relocation_offset, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::external_relocation_offset),
      R"delim(
      Byte offset from the start of the file to the module table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim"_doc)

    .def_prop_rw("nb_external_relocations",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_external_relocations, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_external_relocations),
      R"delim(
      Number of entries in the external relocation table.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim"_doc)

    .def_prop_rw("local_relocation_offset",
      nb::overload_cast<>(&DynamicSymbolCommand::local_relocation_offset, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::local_relocation_offset),
      R"delim(
      Byte offset from the start of the file to the local relocation table data.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim"_doc)

    .def_prop_rw("nb_local_relocations",
      nb::overload_cast<>(&DynamicSymbolCommand::nb_local_relocations, nb::const_),
      nb::overload_cast<uint32_t>(&DynamicSymbolCommand::nb_local_relocations),
      R"delim(
      Number of entries in the local relocation table.
      This field seems unused by recent Mach-O loader and should be set to 0
      )delim"_doc)

    LIEF_DEFAULT_STR(DynamicSymbolCommand);
}
}
