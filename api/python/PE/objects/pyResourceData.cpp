/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/PE/ResourceData.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (ResourceData::*)(void) const;

template<class T>
using setter_t = void (ResourceData::*)(T);

void init_PE_ResourceData_class(py::module& m) {
  py::class_<ResourceData, ResourceNode>(m, "ResourceData")
    .def(py::init<>(),
        "Default constructor")

    .def(py::init<const std::vector<uint8_t>&, uint32_t>(),
        "content"_a, "code_page"_a)

    .def_property("code_page",
        static_cast<getter_t<uint32_t>>(&ResourceData::code_page),
        static_cast<setter_t<uint32_t>>(&ResourceData::code_page),
        "The code page that is used to decode code point "
        "values within the resource data. Typically, the code "
        "page would be the Unicode code page")

    .def_property("content",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&ResourceData::content),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&ResourceData::content),
        "Resource content")

    .def_property("reserved",
        static_cast<getter_t<uint32_t>>(&ResourceData::reserved),
        static_cast<setter_t<uint32_t>>(&ResourceData::reserved),
        "Reserved value. Should be ``0``")

    .def_property_readonly("offset",
        &ResourceData::offset,
        "Offset of the content within the resource")

    .def("__eq__", &ResourceData::operator==)
    .def("__ne__", &ResourceData::operator!=)

    .def("__hash__",
        [] (const ResourceData& node) {
          return Hash::hash(node);
        })

    .def("__str__",
        [] (const ResourceData& data) {
          std::ostringstream stream;
          stream << data;
          std::string str = stream.str();
          return str;
        });
}
