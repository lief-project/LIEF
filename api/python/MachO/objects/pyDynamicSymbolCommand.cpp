/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

template<class T>
using getter_t = T (DynamicSymbolCommand::*)(void) const;

template<class T>
using setter_t = void (DynamicSymbolCommand::*)(T);

template<class T>
using no_const_getter = T (DynamicSymbolCommand::*)(void);

void init_MachO_DynamicSymbolCommand_class(py::module& m) {

  py::class_<DynamicSymbolCommand, LoadCommand>(m, "DynamicSymbolCommand")

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
      "Byte offset from the start of the file to the table of contents data\n\n"

      "Table of content is used by legacy Mach-O loader and this field should be set to 0"
    )

    .def_property("nb_toc",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_toc),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_toc),
      "Number of entries in the table of contents\n\n"

      "Should be set to 0 on recent Mach-O"
    )

    .def_property("module_table_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::module_table_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::module_table_offset),
      "Byte offset from the start of the file to the module table data.\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"
    )

    .def_property("nb_module_table",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_module_table),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_module_table),
      "Number of entries in the module table..\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"
    )

    .def_property("external_reference_symbol_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::external_reference_symbol_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::external_reference_symbol_offset),
      "Byte offset from the start of the file to the external reference table data.\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"
    )

    .def_property("nb_external_reference_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_reference_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_reference_symbols),
      "Number of entries in the external reference table\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"
    )

    .def_property("indirect_symbol_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::indirect_symbol_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::indirect_symbol_offset),
      "Byte offset from the start of the file to the indirect symbol table data..\n\n"

      "Indirect symbol table is used by the loader to speed-up symbol resolution during "
      "the *lazy binding* process\n\n"

      "References:\n\n"
      "\t* ``dyld-519.2.1/src/ImageLoaderMachOCompressed.cpp``\n"
      "\t* ``dyld-519.2.1/src/ImageLoaderMachOClassic.cpp``\n"
    )

    .def_property("nb_indirect_symbols",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_indirect_symbols),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_indirect_symbols),
      "Number of entries in the indirect symbol table."
    )

    .def_property("external_relocation_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::external_relocation_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::external_relocation_offset),
      "Byte offset from the start of the file to the module table data.\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"

    )

    .def_property("nb_external_relocations",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_relocations),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_external_relocations),
      "Number of entries in the external relocation table.\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"

    )

    .def_property("local_relocation_offset",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::local_relocation_offset),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::local_relocation_offset),
      "Byte offset from the start of the file to the local relocation table data.\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"

    )

    .def_property("nb_local_relocations",
      static_cast<getter_t<uint32_t>>(&DynamicSymbolCommand::nb_local_relocations),
      static_cast<setter_t<uint32_t>>(&DynamicSymbolCommand::nb_local_relocations),
      "Number of entries in the local relocation table.\n\n"

      "This field seems unused by recent Mach-O loader and should be set to 0"

    )

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
