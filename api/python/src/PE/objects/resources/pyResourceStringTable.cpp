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
#include "PE/pyPE.hpp"

#include "LIEF/PE/resources/ResourceStringTable.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceStringTable>(nb::module_& m) {
  nb::class_<ResourceStringTable, LIEF::Object>(m, "ResourceStringTable")

    .def_prop_ro("length",
      nb::overload_cast<>(&ResourceStringTable::length, nb::const_),
      "The size of the string, not including length field itself."_doc)

    .def_prop_ro("name",
      nb::overload_cast<>(&ResourceStringTable::name, nb::const_),
      "The variable-length Unicode string data, word-aligned."_doc)

    LIEF_DEFAULT_STR(ResourceStringTable);
}
}
