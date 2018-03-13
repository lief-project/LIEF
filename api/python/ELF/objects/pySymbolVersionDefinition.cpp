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

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"

template<class T>
using getter_t = T (SymbolVersionDefinition::*)(void) const;

template<class T>
using setter_t = void (SymbolVersionDefinition::*)(T);

template<class T>
using no_const_getter = T (SymbolVersionDefinition::*)(void);

void init_ELF_SymbolVersionDefinition_class(py::module& m) {

  py::class_<SymbolVersionDefinition, LIEF::Object>(m, "SymbolVersionDefinition",
      "Class which modelization of an entry defined in ``DT_VERDEF`` (or ``.gnu.version_d``)")

    .def_property("version",
        static_cast<getter_t<uint16_t>>(&SymbolVersionDefinition::version),
        static_cast<setter_t<uint16_t>>(&SymbolVersionDefinition::version),
        "Version revision. Should holds 1")

    .def_property("flags",
        static_cast<getter_t<uint16_t>>(&SymbolVersionDefinition::flags),
        static_cast<setter_t<uint16_t>>(&SymbolVersionDefinition::flags))

    .def_property("hash",
        static_cast<getter_t<uint32_t>>(&SymbolVersionDefinition::hash),
        static_cast<setter_t<uint32_t>>(&SymbolVersionDefinition::hash))

    .def_property_readonly("auxiliary_symbols",
        static_cast<no_const_getter<it_symbols_version_aux>>(&SymbolVersionDefinition::symbols_aux),
        py::return_value_policy::reference_internal)

    .def("__eq__", &SymbolVersionDefinition::operator==)
    .def("__ne__", &SymbolVersionDefinition::operator!=)
    .def("__hash__",
        [] (const SymbolVersionDefinition& svd) {
          return Hash::hash(svd);
        })

    .def("__str__",
        [] (const SymbolVersionDefinition& svd)
        {
          std::ostringstream stream;
          stream << svd;
          std::string str =  stream.str();
          return str;
        });
}
