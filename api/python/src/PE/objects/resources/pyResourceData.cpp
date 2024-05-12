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
#include "nanobind/extra/memoryview.hpp"

#include "LIEF/PE/ResourceData.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<ResourceData>(nb::module_& m) {
  nb::class_<ResourceData, ResourceNode>(m, "ResourceData",
      R"delim(
      Class which represents a Data Node in the PE resources tree
      )delim"_doc)
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def(nb::init<const std::vector<uint8_t>&, uint32_t>(),
        "content"_a, "code_page"_a)

    .def_prop_rw("code_page",
        nb::overload_cast<>(&ResourceData::code_page, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceData::code_page),
        R"delim(
        Return the code page that is used to decode code point
        values within the resource data. Typically, the code page is the Unicode code page.
        )delim"_doc)

    .def_prop_rw("content",
        [] (const ResourceData& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<std::vector<uint8_t>>(&ResourceData::content),
        "Resource content"_doc)

    .def_prop_rw("reserved",
        nb::overload_cast<>(&ResourceData::reserved, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceData::reserved),
        "Reserved value. Should be ``0``"_doc)

    .def_prop_ro("offset",
        &ResourceData::offset,
        R"delim(
        Offset of the content within the resource

        .. warning::

            This value can change when re-building the resource table
        )delim"_doc)

    LIEF_DEFAULT_STR(ResourceData);
}
}
