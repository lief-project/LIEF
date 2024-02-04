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

#include "LIEF/MachO/RelocationObject.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<RelocationObject>(nb::module_& m) {

  nb::class_<RelocationObject, Relocation>(m, "RelocationObject",
      R"delim(
      Class that represents a relocation presents in the MachO object
      file (``.o``). Usually, this kind of relocation is found in the :class:`lief.MachO.Section`.
      )delim"_doc)

    .def_prop_rw("value",
        nb::overload_cast<>(&RelocationObject::value, nb::const_),
        nb::overload_cast<int32_t>(&RelocationObject::value),
        R"delim(
        For **scattered** relocations, the address of the relocatable expression
        for the item in the file that needs to be updated if the address is changed.

        For relocatable expressions with the difference of two section addresses,
        the address from which to subtract (in mathematical terms, the minuend)
        is contained in the first relocation entry and the address to subtract (the subtrahend)
        is contained in the second relocation entry.",
        )delim"_doc)


    .def_prop_ro("is_scattered", &RelocationObject::is_scattered,
        "``True`` if the relocation is a scattered one"_doc)

    LIEF_DEFAULT_STR(RelocationObject);
}

}
