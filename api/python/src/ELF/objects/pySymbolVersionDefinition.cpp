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

#include "pyIterator.hpp"
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"

namespace LIEF::ELF::py {

template<>
void create<SymbolVersionDefinition>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<SymbolVersionDefinition, LIEF::Object> sym_ver_def(m, "SymbolVersionDefinition",
      "Class which represents an entry defined in ``DT_VERDEF`` or ``.gnu.version_d``"_doc);

  init_ref_iterator<SymbolVersionDefinition::it_version_aux>(sym_ver_def, "it_version_aux");
  sym_ver_def
    .def_prop_rw("version",
        nb::overload_cast<>(&SymbolVersionDefinition::version, nb::const_),
        nb::overload_cast<uint16_t>(&SymbolVersionDefinition::version),
        R"delim(
        Version revision. Should be 1

        This field should always have the value ``1``. It will be changed
        if the versioning implementation has to be changed in an incompatible way.
        )delim"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&SymbolVersionDefinition::flags, nb::const_),
        nb::overload_cast<uint16_t>(&SymbolVersionDefinition::flags),
        "Version information"_doc)

    .def_prop_rw("hash",
        nb::overload_cast<>(&SymbolVersionDefinition::hash, nb::const_),
        nb::overload_cast<uint32_t>(&SymbolVersionDefinition::hash),
        "Hash value of the symbol's name (using ELF hash function)"_doc)

    .def_prop_ro("ndx", &SymbolVersionDefinition::ndx,
                 "Numeric value used as an index in the :class`~.ELF.SymbolVersion` table"_doc)

    .def_prop_ro("auxiliary_symbols",
        nb::overload_cast<>(&SymbolVersionDefinition::symbols_aux),
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(SymbolVersionDefinition);
}

}
