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
#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (SymbolVersionAuxRequirement::*)(void) const;

template<class T>
using setter_t = void (SymbolVersionAuxRequirement::*)(T);

void init_ELF_SymbolVersionAuxRequirement_class(py::module& m) {
  //
  // Symbol Version Requirement Auxiliary object
  //
  py::class_<SymbolVersionAuxRequirement, SymbolVersionAux>(m, "SymbolVersionAuxRequirement")
    .def_property("hash",
        static_cast<getter_t<uint32_t>>(&SymbolVersionAuxRequirement::hash),
        static_cast<setter_t<uint32_t>>(&SymbolVersionAuxRequirement::hash))

    .def_property("flags",
        static_cast<getter_t<uint16_t>>(&SymbolVersionAuxRequirement::flags),
        static_cast<setter_t<uint16_t>>(&SymbolVersionAuxRequirement::flags))

    .def_property("other",
        static_cast<getter_t<uint16_t>>(&SymbolVersionAuxRequirement::other),
        static_cast<setter_t<uint16_t>>(&SymbolVersionAuxRequirement::other))


    .def("__eq__", &SymbolVersionAuxRequirement::operator==)
    .def("__ne__", &SymbolVersionAuxRequirement::operator!=)
    .def("__hash__",
        [] (const SymbolVersionAuxRequirement& svar) {
          return Hash::hash(svar);
        })

    .def("__str__",
        [] (const SymbolVersionAuxRequirement& symbolVersionAux)
        {
          std::ostringstream stream;
          stream << symbolVersionAux;
          std::string str =  stream.str();
          return str;
        });
}
