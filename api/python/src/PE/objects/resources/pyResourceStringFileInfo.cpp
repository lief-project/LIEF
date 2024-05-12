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

#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceStringFileInfo>(nb::module_& m) {
  nb::class_<ResourceStringFileInfo, LIEF::Object>(m, "ResourceStringFileInfo",
      R"delim(
      Representation of the ``StringFileInfo`` structure

      See: https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
      )delim"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&ResourceStringFileInfo::type, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceStringFileInfo::type),
        R"delim(
        The type of data in the version resource:

          * ``1`` if it contains text data
          * ``0`` if it contains binary data
        )delim"_doc)

    .def_prop_rw("key",
        nb::overload_cast<>(&ResourceStringFileInfo::key, nb::const_),
        nb::overload_cast<const std::string&>(&ResourceStringFileInfo::key),
        "Signature of the structure. Must be ``StringFileInfo``"_doc)

    .def_prop_rw("langcode_items",
        nb::overload_cast<>(&ResourceStringFileInfo::langcode_items),
        nb::overload_cast<std::vector<LangCodeItem>>(&ResourceStringFileInfo::langcode_items),
        R"delim(
        List of the LangCodeItem items

        Each :attr:`~lief.PE.LangCodeItem.key` indicates the appropriate language and code page
        for displaying the ``key: value`` of :attr:`~lief.PE.LangCodeItem.items`
        )delim"_doc)

    LIEF_DEFAULT_STR(ResourceStringFileInfo);
}
}

