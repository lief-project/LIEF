/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntry>(nb::module_& m) {
  nb::class_<DynamicEntry, LIEF::Object>(m, "DynamicEntry",
      R"delim(
      Class which represents an entry in the dynamic table
      These entries are located in the ``.dynamic`` section or the ``PT_DYNAMIC`` segment
      )delim"_doc)
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def(nb::init<DYNAMIC_TAGS, uint64_t>(),
        "Constructor from a " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " and value"_doc,
        "tag"_a, "value"_a)

    .def_prop_rw("tag",
        nb::overload_cast<>(&DynamicEntry::tag, nb::const_),
        nb::overload_cast<DYNAMIC_TAGS>(&DynamicEntry::tag),
        "Return the entry's " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " which represent the entry type"_doc)

    .def_prop_rw("value",
        nb::overload_cast<>(&DynamicEntry::value, nb::const_),
        nb::overload_cast<uint64_t>(&DynamicEntry::value),
        R"delim(
        Return the entry's value

        The meaning of the value strongly depends on the tag.
        It can be an offset, an index, a flag, ...
        )delim"_doc)

    LIEF_DEFAULT_STR(DynamicEntry);
}

}
