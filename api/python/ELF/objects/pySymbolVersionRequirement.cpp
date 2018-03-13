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
#include <string>
#include <sstream>

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"

#include "pyELF.hpp"

template<class T>
using getter_t = T (SymbolVersionRequirement::*)(void) const;

template<class T>
using setter_t = void (SymbolVersionRequirement::*)(T);

template<class T>
using no_const_getter = T (SymbolVersionRequirement::*)(void);

void init_ELF_SymbolVersionRequirement_class(py::module& m) {

  // Symbol Version Requirement object
  py::class_<SymbolVersionRequirement, LIEF::Object>(m, "SymbolVersionRequirement",
      "Class which modelize an entry in ``DT_VERNEED`` or ``.gnu.version_r`` table")

    .def_property("version",
        static_cast<getter_t<uint16_t>>(&SymbolVersionRequirement::version),
        static_cast<setter_t<uint16_t>>(&SymbolVersionRequirement::version),
        "Version revision. Should holds 1")

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&SymbolVersionRequirement::name),
        static_cast<setter_t<const std::string&>>(&SymbolVersionRequirement::name))

    .def("get_auxiliary_symbols",
        static_cast<no_const_getter<it_symbols_version_aux_requirement>>(&SymbolVersionRequirement::auxiliary_symbols),
        "Auxiliary entries",
        py::return_value_policy::reference_internal)

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
