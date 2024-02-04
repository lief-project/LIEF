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
#include <nanobind/stl/string.h>

#include "LIEF/PE/ParserConfig.hpp"

#include "PE/pyPE.hpp"

namespace LIEF::PE::py {

template<>
void create<ParserConfig>(nb::module_& m) {

  nb::class_<ParserConfig>(m, "ParserConfig",
      R"delim(
      This class is used to tweak the PE Parser (:class:`~lief.PE.Parser`)
      )delim"_doc)

    .def(nb::init<>())
    .def_rw("parse_signature", &ParserConfig::parse_signature,
            "Parse PE Authenticode signature"_doc)

    .def_rw("parse_exports", &ParserConfig::parse_exports,
            "Parse PE Exports Directory"_doc)

    .def_rw("parse_imports", &ParserConfig::parse_imports,
            "Parse PE Import Directory"_doc)

    .def_rw("parse_rsrc", &ParserConfig::parse_rsrc,
            "Parse PE resources tree"_doc)

    .def_rw("parse_reloc", &ParserConfig::parse_reloc,
             "Parse PE relocations"_doc)

    .def_prop_ro_static("all",
      [] (const nb::object& /* self */) { return ParserConfig::all(); },
      R"delim(
      Return a parser configuration such as all the objects supported by LIEF are parsed
      )delim"_doc);

}

}
