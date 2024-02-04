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

#include "LIEF/MachO/SymbolCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<SymbolCommand>(nb::module_& m) {

  nb::class_<SymbolCommand, LoadCommand>(m, "SymbolCommand",
      R"delim(Class that represents the LC_SYMTAB command)delim"_doc)
    .def(nb::init<>())

    .def_prop_rw("symbol_offset",
        nb::overload_cast<>(&SymbolCommand::symbol_offset, nb::const_),
        nb::overload_cast<uint32_t>(&SymbolCommand::symbol_offset),
        "Offset from the start of the file to the n_list associated with the command"_doc)

    .def_prop_rw("numberof_symbols",
        nb::overload_cast<>(&SymbolCommand::numberof_symbols, nb::const_),
        nb::overload_cast<uint32_t>(&SymbolCommand::numberof_symbols),
        "Number of symbols registered"_doc)

    .def_prop_rw("strings_offset",
        nb::overload_cast<>(&SymbolCommand::strings_offset, nb::const_),
        nb::overload_cast<uint32_t>(&SymbolCommand::strings_offset),
        "Offset from the start of the file to the string table"_doc)

    .def_prop_rw("strings_size",
        nb::overload_cast<>(&SymbolCommand::strings_size, nb::const_),
        nb::overload_cast<uint32_t>(&SymbolCommand::strings_size),
        "Size of the size string table"_doc)

    LIEF_DEFAULT_STR(SymbolCommand);
}
}


