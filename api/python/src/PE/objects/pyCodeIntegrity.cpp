
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
#include "PE/pyPE.hpp"

#include "LIEF/PE/CodeIntegrity.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<CodeIntegrity>(nb::module_& m) {
  nb::class_<CodeIntegrity, LIEF::Object>(m, "CodeIntegrity")
    .def(nb::init<>())

    .def_prop_rw("flags",
        nb::overload_cast<>(&CodeIntegrity::flags, nb::const_),
        nb::overload_cast<uint16_t>(&CodeIntegrity::flags),
        "Flags to indicate if CI information is available, etc."_doc)

    .def_prop_rw("catalog",
        nb::overload_cast<>(&CodeIntegrity::catalog, nb::const_),
        nb::overload_cast<uint16_t>(&CodeIntegrity::catalog),
        "``0xFFFF`` means not available"_doc)

    .def_prop_rw("catalog_offset",
        nb::overload_cast<>(&CodeIntegrity::catalog_offset, nb::const_),
        nb::overload_cast<uint32_t>(&CodeIntegrity::catalog_offset))

    .def_prop_rw("reserved",
        nb::overload_cast<>(&CodeIntegrity::reserved, nb::const_),
        nb::overload_cast<uint32_t>(&CodeIntegrity::reserved),
        "Additional bitmask to be defined later"_doc)

    LIEF_DEFAULT_STR(CodeIntegrity);
}

}
