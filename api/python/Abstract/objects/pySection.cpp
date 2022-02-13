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
#include <sstream>
#include "pyAbstract.hpp"
#include "LIEF/Abstract/Section.hpp"

namespace LIEF {
template<class T>
using getter_t = T (Section::*)(void) const;

template<class T>
using setter_t = void (Section::*)(T);

template<>
void create<Section>(py::module& m) {
  py::class_<Section, Object>(m, "Section",
      R"delim(
      Class which represents an abstracted section
      )delim")
    .def(py::init(),
        "Default constructor")

    .def(py::init<const std::string&>(),
        "Constructor from section name",
        "name"_a)

    .def_property("name",
        [] (const Section& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&Section::name),
        "Section's name")

    .def_property_readonly("fullname",
        &Section::fullname,
        "Return the **fullname** of the section including the trailing bytes")

    .def_property("size",
        static_cast<getter_t<uint64_t>>(&Section::size),
        static_cast<setter_t<uint64_t>>(&Section::size),
        "Section's size")

    .def_property("offset",
        static_cast<getter_t<uint64_t>>(&Section::offset),
        static_cast<setter_t<uint64_t>>(&Section::offset),
        "Section's file offset")

    .def_property("virtual_address",
        static_cast<getter_t<uint64_t>>(&Section::virtual_address),
        static_cast<setter_t<uint64_t>>(&Section::virtual_address),
        "Section's virtual address")

    .def_property("content",
        [] (const Section& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<const std::vector<uint8_t>&>>(&Section::content),
        "Section's content")

    .def_property_readonly("entropy",
        &Section::entropy,
        "Section's entropy")

    .def("search",
        static_cast<size_t (Section::*)(uint64_t, size_t, size_t) const>(&Section::search),
        "Look for **integer** within the current section",
        "number"_a, "pos"_a = 0, "size"_a = 0)

    .def("search",
        static_cast<size_t (Section::*)(const std::string&, size_t) const>(&Section::search),
        "Look for **string** within the current section",
        "str"_a, "pos"_a = 0)

    .def("search_all",
        static_cast<std::vector<size_t> (Section::*)(uint64_t, size_t) const>(&Section::search_all),
        "Look for **all** integers within the current section",
        "number"_a, "size"_a = 0)

    .def("search_all",
        static_cast<std::vector<size_t> (Section::*)(const std::string&) const>(&Section::search_all),
        "Look for all **strings** within the current section",
        "str"_a)

    .def("__str__",
        [] (const Section& section)
        {
          std::ostringstream stream;
          stream << section;
          std::string str =  stream.str();
          return str;
        });
}
}
