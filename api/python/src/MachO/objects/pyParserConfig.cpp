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

#include "LIEF/MachO/ParserConfig.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<ParserConfig>(nb::module_& m) {

  nb::class_<ParserConfig>(m, "ParserConfig",
      R"delim(
      This class is used to tweak the MachO Parser (:class:`~lief.MachO.Parser`)
      )delim"_doc)

    .def(nb::init<>())
    .def_rw("parse_dyld_exports", &ParserConfig::parse_dyld_exports,
            "Parse the Dyld export trie"_doc)

    .def_rw("parse_dyld_bindings", &ParserConfig::parse_dyld_bindings,
            "Parse the Dyld binding opcodes"_doc)

    .def_rw("parse_dyld_rebases", &ParserConfig::parse_dyld_rebases,
            "Parse the Dyld rebase opcodes"_doc)

    .def_rw("fix_from_memory", &ParserConfig::fix_from_memory,
            R"delim(
            When parsing Mach-O from memory, this option
            can be used to *undo* relocations and symbols bindings.

            When activated, this option requires parse_dyld_bindings
            and parse_dyld_rebases to be enabled.
            )delim"_doc)

    .def("full_dyldinfo", &ParserConfig::full_dyldinfo,
         R"delim(
         If ``flag`` is set to ``true``, Exports, Bindings and Rebases opcodes are parsed.

         .. warning::

            Enabling this flag can slow down the parsing
         )delim"_doc, "flag"_a)

    .def_prop_ro_static("deep",
      [] (const nb::object& /* self */) { return ParserConfig::deep(); },
      R"delim(
      Return a parser configuration such as all the objects supported by LIEF are parsed
      )delim"_doc)

    .def_prop_ro_static("quick",
      [] (const nb::object& /* self */) { return ParserConfig::quick(); },
      R"delim(
      Return a configuration to parse the most important MachO structures
      )delim"_doc);
}
}
