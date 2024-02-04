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

#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"

#include "pyIterator.hpp"
#include "ELF/pyELF.hpp"

namespace LIEF::ELF::py {

template<>
void create<SymbolVersionRequirement>(nb::module_& m) {
  using namespace LIEF::py;

  // Symbol Version Requirement object
  nb::class_<SymbolVersionRequirement, LIEF::Object> sym_ver_req(m, "SymbolVersionRequirement",
      "Class which represents an entry in the ``DT_VERNEED`` or ``.gnu.version_r`` table"_doc);

  init_ref_iterator<SymbolVersionRequirement::it_aux_requirement>(sym_ver_req, "it_aux_requirement");

  sym_ver_req
    .def_prop_rw("version",
        nb::overload_cast<>(&SymbolVersionRequirement::version, nb::const_),
        nb::overload_cast<uint16_t>(&SymbolVersionRequirement::version),
        "Version revision. Should be 1"_doc)

    .def_prop_rw("name",
        nb::overload_cast<>(&SymbolVersionRequirement::name, nb::const_),
        nb::overload_cast<const std::string&>(&SymbolVersionRequirement::name),
        "Library's name associated with this requirement (e.g. ``libc.so.6``)"_doc)

    .def("get_auxiliary_symbols",
        nb::overload_cast<>(&SymbolVersionRequirement::auxiliary_symbols),
        "Auxiliary entries (iterator over " RST_CLASS_REF(lief.ELF.SymbolVersionAuxRequirement) ")"_doc,
        nb::rv_policy::reference_internal)

    .def("add_auxiliary_requirement",
        static_cast<SymbolVersionAuxRequirement& (SymbolVersionRequirement::*)(const SymbolVersionAuxRequirement&)>(&SymbolVersionRequirement::add_aux_requirement),
        "Add an auxiliary version requirement to the existing entries"_doc)

    LIEF_DEFAULT_STR(SymbolVersionRequirement);
}

}
