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

#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::ELF::py {

template<>
void create<SymbolVersionAuxRequirement>(nb::module_& m) {
  nb::class_<SymbolVersionAuxRequirement, SymbolVersionAux>(m, "SymbolVersionAuxRequirement")
    .def(nb::init<>(),"Default constructor"_doc)

    .def_prop_rw("hash",
        nb::overload_cast<>(&SymbolVersionAuxRequirement::hash, nb::const_),
        nb::overload_cast<uint32_t>(&SymbolVersionAuxRequirement::hash),
        "Hash value of the dependency name (use ELF hashing function)"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&SymbolVersionAuxRequirement::flags, nb::const_),
        nb::overload_cast<uint16_t>(&SymbolVersionAuxRequirement::flags),
        "Bitmask of flags"_doc)

    .def_prop_rw("other",
        nb::overload_cast<>(&SymbolVersionAuxRequirement::other, nb::const_),
        nb::overload_cast<uint16_t>(&SymbolVersionAuxRequirement::other),
        R"delim(
        It returns the unique version index for the file which is used in the
        version symbol table. If the highest bit (bit 15) is set this
        is a hidden symbol which cannot be referenced from outside the
        object.
        )delim"_doc)

    LIEF_DEFAULT_STR(SymbolVersionAuxRequirement);

}
}
