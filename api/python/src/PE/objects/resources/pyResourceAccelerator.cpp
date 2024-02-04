/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#include <sstream>
#include <string>
#include <nanobind/stl/string.h>

#include "PE/pyPE.hpp"

#include "LIEF/PE/resources/ResourceAccelerator.hpp"

namespace LIEF::PE::py {

template<>
void create<ResourceAccelerator>(nb::module_& m) {
  nb::class_<ResourceAccelerator, LIEF::Object>(m, "ResourceAccelerator")

    .def_prop_ro("flags",
      nb::overload_cast<>(&ResourceAccelerator::flags, nb::const_),
      "Describe the keyboard accelerator characteristics."_doc)

    .def_prop_ro("ansi",
      nb::overload_cast<>(&ResourceAccelerator::ansi, nb::const_),
      "An ANSI character value or a virtual-key code that identifies the accelerator key."_doc)

    .def_prop_ro("id",
      nb::overload_cast<>(&ResourceAccelerator::id, nb::const_),
      "An identifier for the keyboard accelerator."_doc)

    .def_prop_ro("padding",
      nb::overload_cast<>(&ResourceAccelerator::padding, nb::const_),
      "The number of bytes inserted to ensure that the structure is aligned on a DWORD boundary."_doc)

    LIEF_DEFAULT_STR(ResourceAccelerator);
}
}
