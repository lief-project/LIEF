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
  py::class_<LIEF::Section>(m, "Section")
    .def(py::init())

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
        "Section's entropy");
}
