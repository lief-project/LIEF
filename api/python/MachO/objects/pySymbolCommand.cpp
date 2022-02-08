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
#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (SymbolCommand::*)(void) const;

template<class T>
using setter_t = void (SymbolCommand::*)(T);


template<>
void create<SymbolCommand>(py::module& m) {

  py::class_<SymbolCommand, LoadCommand>(m, "SymbolCommand",
      R"delim(
      Class that represents the LC_SYMTAB command
      )delim")
    .def(py::init<>())

    .def_property("symbol_offset",
        static_cast<getter_t<uint32_t>>(&SymbolCommand::symbol_offset),
        static_cast<setter_t<uint32_t>>(&SymbolCommand::symbol_offset),
        "Offset from the start of the file to the n_list associated with the command")

    .def_property("numberof_symbols",
        static_cast<getter_t<uint32_t>>(&SymbolCommand::numberof_symbols),
        static_cast<setter_t<uint32_t>>(&SymbolCommand::numberof_symbols),
        "Number of symbols registered")

    .def_property("strings_offset",
        static_cast<getter_t<uint32_t>>(&SymbolCommand::strings_offset),
        static_cast<setter_t<uint32_t>>(&SymbolCommand::strings_offset),
        "Offset from the start of the file to the string table")

    .def_property("strings_size",
        static_cast<getter_t<uint32_t>>(&SymbolCommand::strings_size),
        static_cast<setter_t<uint32_t>>(&SymbolCommand::strings_size),
        "Size of the size string table")


    .def("__eq__", &SymbolCommand::operator==)
    .def("__ne__", &SymbolCommand::operator!=)
    .def("__hash__",
        [] (const SymbolCommand& symbolcmd) {
          return Hash::hash(symbolcmd);
        })

    .def("__str__",
        [] (const SymbolCommand& symbolcmd)
        {
          std::ostringstream stream;
          stream << symbolcmd;
          std::string str =  stream.str();
          return str;
        });

}

}
}


