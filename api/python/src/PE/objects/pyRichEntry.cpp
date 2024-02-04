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

#include "LIEF/PE/RichEntry.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<RichEntry>(nb::module_& m) {
  nb::class_<RichEntry, Object>(m, "RichEntry",
      R"delim(
      Class which represents an entry associated to the RichHeader
      )delim"_doc)
    .def(nb::init<>())
    .def(nb::init<uint16_t, uint16_t, uint32_t>(),
        "Contructor from "
        ":attr:`~lief.PE.RichEntry.id`, "
        ":attr:`~lief.PE.RichEntry.build_id` and "
        ":attr:`~lief.PE.RichEntry.count`"_doc,
        "id"_a, "build_id"_a, "count"_a)

    .def_prop_rw("id",
        nb::overload_cast<>(&RichEntry::id, nb::const_),
        nb::overload_cast<uint16_t>(&RichEntry::id),
        "Type of the entry"_doc)

    .def_prop_rw("build_id",
        nb::overload_cast<>(&RichEntry::build_id, nb::const_),
        nb::overload_cast<uint16_t>(&RichEntry::build_id),
        "Builder number of the tool (if any)"_doc)

    .def_prop_rw("count",
        nb::overload_cast<>(&RichEntry::count, nb::const_),
        nb::overload_cast<uint32_t>(&RichEntry::count),
        "*Occurrence* count"_doc)

    LIEF_COPYABLE(RichEntry)
    LIEF_DEFAULT_STR(RichEntry);
}

}
