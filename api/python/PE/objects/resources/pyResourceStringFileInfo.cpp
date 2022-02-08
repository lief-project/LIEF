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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceStringFileInfo::*)(void) const;

template<class T>
using setter_t = void (ResourceStringFileInfo::*)(T);


template<>
void create<ResourceStringFileInfo>(py::module& m) {
  py::class_<ResourceStringFileInfo, LIEF::Object>(m, "ResourceStringFileInfo",
      R"delim(
      Representation of the ``StringFileInfo`` structure

      See: https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
      )delim")


    .def_property("type",
        static_cast<getter_t<uint16_t>>(&ResourceStringFileInfo::type),
        static_cast<setter_t<uint16_t>>(&ResourceStringFileInfo::type),
        R"delim(
        The type of data in the version resource:

          * ``1`` if it contains text data
          * ``0`` if it contains binary data
        )delim")

    .def_property("key",
        static_cast<getter_t<const std::u16string&>>(&ResourceStringFileInfo::key),
        static_cast<setter_t<const std::string&>>(&ResourceStringFileInfo::key),
        "Signature of the structure. Must be ``StringFileInfo``")

    .def_property("langcode_items",
        static_cast<std::vector<LangCodeItem>& (ResourceStringFileInfo::*)(void)>(&ResourceStringFileInfo::langcode_items),
        static_cast<setter_t<const std::vector<LangCodeItem>&>>(&ResourceStringFileInfo::langcode_items),
        R"delim(
        List of the LangCodeItem items

        Each :attr:`~lief.PE.LangCodeItem.key` indicates the appropriate language and code page
        for displaying the ``key: value`` of :attr:`~lief.PE.LangCodeItem.items`
        )delim")

    .def("__eq__", &ResourceStringFileInfo::operator==)
    .def("__ne__", &ResourceStringFileInfo::operator!=)
    .def("__hash__",
        [] (const ResourceStringFileInfo& string_file_info) {
          return Hash::hash(string_file_info);
        })

    .def("__str__",
        [] (const ResourceStringFileInfo& string_file_info) {
          std::ostringstream stream;
          stream << string_file_info;
          std::string str = stream.str();
          return str;
        });
}

}
}

