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
#include "init.hpp"
#include "LIEF/Abstract/Section.hpp"

template<class T>
using getter_t = T (LIEF::Section::*)(void) const;

template<class T>
using setter_t = void (LIEF::Section::*)(T);

void init_LIEF_Section_class(py::module& m) {
  py::class_<LIEF::Section, LIEF::Object>(m, "Section")
    .def(py::init(),
        "Default constructor")

    .def(py::init<const std::string&>(),
        "Constructor from section name",
        "name"_a)

    .def_property("name",
        [] (const LIEF::Section& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&LIEF::Section::name),
        "Section's name")

    .def_property("size",
        static_cast<getter_t<uint64_t>>(&LIEF::Section::size),
        static_cast<setter_t<uint64_t>>(&LIEF::Section::size),
        "Section's size")

    .def_property("offset",
        static_cast<getter_t<uint64_t>>(&LIEF::Section::offset),
        static_cast<setter_t<uint64_t>>(&LIEF::Section::offset),
        "Section's offset")

    .def_property("virtual_address",
        static_cast<getter_t<uint64_t>>(&LIEF::Section::virtual_address),
        static_cast<setter_t<uint64_t>>(&LIEF::Section::virtual_address),
        "Section's size")

    .def_property("content",
        static_cast<getter_t<std::vector<uint8_t>>>(&LIEF::Section::content),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&LIEF::Section::content),
        "Section's content")

    .def_property_readonly("entropy",
        &LIEF::Section::entropy,
        "Section's entropy")

    .def("search",
        static_cast<size_t (LIEF::Section::*)(uint64_t, size_t, size_t) const>(&LIEF::Section::search),
        "Look for **integer** within the current section",
        "number"_a, "pos"_a = 0, "size"_a = 0)

    .def("search",
        static_cast<size_t (LIEF::Section::*)(const std::string&, size_t) const>(&LIEF::Section::search),
        "Look for **string** within the current section",
        "str"_a, "pos"_a = 0)

    .def("search_all",
        static_cast<std::vector<size_t> (LIEF::Section::*)(uint64_t, size_t) const>(&LIEF::Section::search_all),
        "Look for **all** integers within the current section",
        "number"_a, "size"_a = 0)

    .def("search_all",
        static_cast<std::vector<size_t> (LIEF::Section::*)(const std::string&) const>(&LIEF::Section::search_all),
        "Look for all **strings** within the current section",
        "str"_a)

    .def("__str__",
        [] (const LIEF::Section& section)
        {
          std::ostringstream stream;
          stream << section;
          std::string str =  stream.str();
          return str;
        });


}
