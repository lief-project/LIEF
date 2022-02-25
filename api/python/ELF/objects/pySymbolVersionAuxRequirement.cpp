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
#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (SymbolVersionAuxRequirement::*)(void) const;

template<class T>
using setter_t = void (SymbolVersionAuxRequirement::*)(T);


template<>
void create<SymbolVersionAuxRequirement>(py::module& m) {
  py::class_<SymbolVersionAuxRequirement, SymbolVersionAux>(m, "SymbolVersionAuxRequirement")
    .def(py::init<>(),"Default constructor")

    .def_property("hash",
        static_cast<getter_t<uint32_t>>(&SymbolVersionAuxRequirement::hash),
        static_cast<setter_t<uint32_t>>(&SymbolVersionAuxRequirement::hash),
        "Hash value of the dependency name (use ELF hashing function)")

    .def_property("flags",
        static_cast<getter_t<uint16_t>>(&SymbolVersionAuxRequirement::flags),
        static_cast<setter_t<uint16_t>>(&SymbolVersionAuxRequirement::flags),
        "Bitmask of flags")

    .def_property("other",
        static_cast<getter_t<uint16_t>>(&SymbolVersionAuxRequirement::other),
        static_cast<setter_t<uint16_t>>(&SymbolVersionAuxRequirement::other),
        R"delim(
        It returns the unique version index for the file which is used in the
        version symbol table. If the highest bit (bit 15) is set this
        is a hidden symbol which cannot be referenced from outside the
        object.
        )delim")


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

}
}
