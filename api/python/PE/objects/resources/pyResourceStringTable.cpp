/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/ResourceStringTable.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceStringTable::*)(void) const;

template<class T>
using setter_t = void (ResourceStringTable::*)(T);


template<>
void create<ResourceStringTable>(py::module& m) {
  py::class_<ResourceStringTable, LIEF::Object>(m, "ResourceStringTable")

    .def_property_readonly("length",
      static_cast<getter_t<int16_t>>(&ResourceStringTable::length),
      "The size of the string, not including length field itself.")

    .def_property_readonly("name",
      static_cast<getter_t<const std::u16string&>>(&ResourceStringTable::name),
      "The variable-length Unicode string data, word-aligned."
    )

    .def("__eq__", &ResourceStringTable::operator==)
    .def("__ne__", &ResourceStringTable::operator!=)
    .def("__hash__",
        [] (const ResourceStringTable& string_table) {
          return Hash::hash(string_table);
        })

    .def("__str__",
        [] (const ResourceStringTable& string_table) {
          std::ostringstream stream;
          stream << string_table;
          std::string str = stream.str();
          return str;
        });
}

}
}
