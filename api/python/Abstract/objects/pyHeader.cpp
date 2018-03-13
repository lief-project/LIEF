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
#include <sstream>

#include "init.hpp"
#include "LIEF/Abstract/Header.hpp"

template<class T>
using getter_t = T (LIEF::Header::*)(void) const;

template<class T>
using setter_t = void (LIEF::Header::*)(T);

void init_LIEF_Header_class(py::module& m) {
  py::class_<LIEF::Header, LIEF::Object>(m, "Header")
    .def(py::init())

    .def_property("architecture",
        static_cast<getter_t<LIEF::ARCHITECTURES>>(&LIEF::Header::architecture),
        static_cast<setter_t<LIEF::ARCHITECTURES>>(&LIEF::Header::architecture),
        "Target architecture (" RST_CLASS_REF(lief.ARCHITECTURES) ")")

    .def_property("modes",
        static_cast<getter_t<const std::set<LIEF::MODES>&>>(&LIEF::Header::modes),
        static_cast<setter_t<const std::set<LIEF::MODES>&>>(&LIEF::Header::modes),
        "Target " RST_CLASS_REF(lief.MODES) " (32-bits, 64-bits...)")

    .def_property("entrypoint",
        static_cast<getter_t<uint64_t>>(&LIEF::Header::entrypoint),
        static_cast<setter_t<uint64_t>>(&LIEF::Header::entrypoint),
        "Binary entrypoint")

    .def_property("object_type",
        static_cast<getter_t<LIEF::OBJECT_TYPES>>(&LIEF::Header::object_type),
        static_cast<setter_t<LIEF::OBJECT_TYPES>>(&LIEF::Header::object_type),
        "Type of the binary (executable, library...)\n"
        "See: " RST_CLASS_REF(lief.OBJECT_TYPES) "")

    .def_property("endianness",
        static_cast<getter_t<LIEF::ENDIANNESS>>(&LIEF::Header::endianness),
        static_cast<setter_t<LIEF::ENDIANNESS>>(&LIEF::Header::endianness),
        "Binary endianness\n"
        "See: " RST_CLASS_REF(lief.ENDIANNESS) "")

    .def_property_readonly("is_32",
        &LIEF::Header::is_32,
        "``True`` if the binary target a ``32-bits`` architecture")

    .def_property_readonly("is_64",
        &LIEF::Header::is_64,
        "``True`` if the binary target a ``64-bits`` architecture")


    .def("__str__",
        [] (const LIEF::Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}
