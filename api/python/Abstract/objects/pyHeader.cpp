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
#include "LIEF/Abstract/Header.hpp"

namespace LIEF {
template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

template<>
void create<Header>(py::module& m) {
  py::class_<Header, Object>(m, "Header")
    .def(py::init())

    .def_property("architecture",
        static_cast<getter_t<ARCHITECTURES>>(&Header::architecture),
        static_cast<setter_t<ARCHITECTURES>>(&Header::architecture),
        "Target architecture (" RST_CLASS_REF(lief.ARCHITECTURES) ")")

    .def_property("modes",
        static_cast<getter_t<const std::set<MODES>&>>(&Header::modes),
        static_cast<setter_t<const std::set<MODES>&>>(&Header::modes),
        "Target " RST_CLASS_REF(lief.MODES) " (32-bits, 64-bits...)")

    .def_property("entrypoint",
        static_cast<getter_t<uint64_t>>(&Header::entrypoint),
        static_cast<setter_t<uint64_t>>(&Header::entrypoint),
        "Binary entrypoint")

    .def_property("object_type",
        static_cast<getter_t<OBJECT_TYPES>>(&Header::object_type),
        static_cast<setter_t<OBJECT_TYPES>>(&Header::object_type),
        "Type of the binary (executable, library...)\n"
        "See: " RST_CLASS_REF(lief.OBJECT_TYPES) "")

    .def_property("endianness",
        static_cast<getter_t<ENDIANNESS>>(&Header::endianness),
        static_cast<setter_t<ENDIANNESS>>(&Header::endianness),
        "Binary endianness\n"
        "See: " RST_CLASS_REF(lief.ENDIANNESS) "")

    .def_property_readonly("is_32",
        &Header::is_32,
        "``True`` if the binary targets a ``32-bits`` architecture")

    .def_property_readonly("is_64",
        &Header::is_64,
        "``True`` if the binary targets a ``64-bits`` architecture")


    .def("__str__",
        [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}
}
