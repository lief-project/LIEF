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
#include "ELF/pyELF.hpp"
#include "LIEF/ELF/ParserConfig.hpp"

#include "enums_wrapper.hpp"

namespace LIEF::ELF::py {

template<>
void create<ParserConfig>(nb::module_& m) {

  nb::class_<ParserConfig> pconfig(m, "ParserConfig",
      R"delim(
      This class is used to tweak the ELF Parser
      )delim"_doc);

  enum_<ParserConfig::DYNSYM_COUNT>(pconfig, "DYNSYM_COUNT")
    .value("AUTO", ParserConfig::DYNSYM_COUNT::AUTO)
    .value("SECTION", ParserConfig::DYNSYM_COUNT::SECTION)
    .value("HASH", ParserConfig::DYNSYM_COUNT::HASH)
    .value("RELOCATIONS", ParserConfig::DYNSYM_COUNT::RELOCATIONS);

  pconfig
    .def(nb::init<>())
    .def_rw("parse_relocations", &ParserConfig::parse_relocations,
            "Whether relocations (including plt-like relocations) should be parsed."_doc)
    .def_rw("parse_dyn_symbols", &ParserConfig::parse_dyn_symbols,
            "Whether dynamic symbols (those from `.dynsym`) should be parsed"_doc)
    .def_rw("parse_symtab_symbols", &ParserConfig::parse_symtab_symbols,
            "Whether debug symbols (those from `.symtab`) should be parsed"_doc)
    .def_rw("parse_symbol_versions", &ParserConfig::parse_symbol_versions,
            "Whether versioning symbols should be parsed"_doc)
    .def_rw("parse_notes", &ParserConfig::parse_notes,
            "Whether ELF notes  information should be parsed"_doc)
    .def_rw("parse_overlay", &ParserConfig::parse_overlay,
            "Whether the overlay data should be parsed")
    .def_rw("count_mtd", &ParserConfig::count_mtd,
            R"delim(
            The :class:`~lief.ELF.DYNSYM_COUNT_METHODS` to use for counting the dynamic symbols

            For *weird* binaries (e.g sectionless) you can choose the method for counting dynamic symbols
            (:class:`lief.ELF.DYNSYM_COUNT_METHODS`). By default, the value is set to
            :attr:`lief.ELF.DYNSYM_COUNT_METHODS.COUNT_AUTO`
            )delim"_doc)

    .def_prop_ro_static("all",
      [] (const nb::object& /* self */) { return ParserConfig::all(); },
      R"delim(
      Return a parser configuration such as all the objects supported by LIEF are parsed
      )delim"_doc);
}

}

