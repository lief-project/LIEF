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

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"

#include "pyIterators.hpp"
#include "pyELF.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (SymbolVersionRequirement::*)(void) const;

template<class T>
using setter_t = void (SymbolVersionRequirement::*)(T);

template<class T>
using no_const_getter = T (SymbolVersionRequirement::*)(void);


template<>
void create<SymbolVersionRequirement>(py::module& m) {

  // Symbol Version Requirement object
  py::class_<SymbolVersionRequirement, LIEF::Object> sym_ver_req(m, "SymbolVersionRequirement",
      "Class which represents an entry in the ``DT_VERNEED`` or ``.gnu.version_r`` table");

  init_ref_iterator<SymbolVersionRequirement::it_aux_requirement>(sym_ver_req, "it_aux_requirement");

  sym_ver_req
    .def_property("version",
        static_cast<getter_t<uint16_t>>(&SymbolVersionRequirement::version),
        static_cast<setter_t<uint16_t>>(&SymbolVersionRequirement::version),
        "Version revision. Should be 1")

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&SymbolVersionRequirement::name),
        static_cast<setter_t<const std::string&>>(&SymbolVersionRequirement::name),
        "Library's name associated with this requirement (e.g. ``libc.so.6``)")

    .def("get_auxiliary_symbols",
        static_cast<no_const_getter<SymbolVersionRequirement::it_aux_requirement>>(&SymbolVersionRequirement::auxiliary_symbols),
        "Auxiliary entries (iterator over " RST_CLASS_REF(lief.ELF.SymbolVersionAuxRequirement) ")",
        py::return_value_policy::reference_internal)

    .def("add_auxiliary_requirement",
        static_cast<SymbolVersionAuxRequirement& (SymbolVersionRequirement::*)(const SymbolVersionAuxRequirement&)>(&SymbolVersionRequirement::add_aux_requirement),
        "Add an auxiliary version requirement to the existing entries")

    .def("__eq__", &SymbolVersionRequirement::operator==)
    .def("__ne__", &SymbolVersionRequirement::operator!=)
    .def("__hash__",
        [] (const SymbolVersionRequirement& svr) {
          return Hash::hash(svr);
        })

    .def("__str__",
        [] (const SymbolVersionRequirement& symbolVersionRequirement)
        {
          std::ostringstream stream;
          stream << symbolVersionRequirement;
          std::string str =  stream.str();
          return str;
        });
}

}
}
