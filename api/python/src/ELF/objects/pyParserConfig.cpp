/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "LIEF/ELF/ParserConfig.hpp"

#include "pyELF.hpp"

namespace LIEF {
namespace ELF {

template<>
void create<ParserConfig>(py::module& m) {

  py::class_<ParserConfig>(m, "ParserConfig",
      R"delim(
      This class is used to tweak the ELF Parser (:class:`~lief.ELF.Parser`)
      )delim")

    .def(py::init<>())
    .def_readwrite("parse_relocations", &ParserConfig::parse_relocations,
                   "Whether relocations (including plt-like relocations) should be parsed.")
    .def_readwrite("parse_dyn_symbols", &ParserConfig::parse_dyn_symbols,
                   "Whether dynamic symbols (those from `.dynsym`) should be parsed")
    .def_readwrite("parse_static_symbols", &ParserConfig::parse_static_symbols,
                   "Whether debug symbols (those from `.symtab`) should be parsed")
    .def_readwrite("parse_symbol_versions", &ParserConfig::parse_symbol_versions,
                   "Whether versioning symbols should be parsed")
    .def_readwrite("parse_notes", &ParserConfig::parse_notes,
                   "Whether ELF notes information should be parsed")
    .def_readwrite("parse_overlay", &ParserConfig::parse_overlay,
                   "Whether the overlay data should be parsed")
    .def_readwrite("count_mtd", &ParserConfig::count_mtd,
                   R"delim(
                   The :class:`~lief.ELF.DYNSYM_COUNT_METHODS` to use for counting the dynamic symbols

                   For *weird* binaries (e.g sectionless) you can choose the method for counting dynamic symbols
                   (:class:`lief.ELF.DYNSYM_COUNT_METHODS`). By default, the value is set to
                   :attr:`lief.ELF.DYNSYM_COUNT_METHODS.COUNT_AUTO`
                   )delim")

    .def_property_readonly_static("all",
      [] (py::object /* self */) { return ParserConfig::all(); },
      R"delim(
      Return a parser configuration such as all the objects supported by LIEF are parsed
      )delim");

}

}
}
