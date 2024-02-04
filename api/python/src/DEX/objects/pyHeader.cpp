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
#include "LIEF/DEX/Header.hpp"

#include "DEX/pyDEX.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/pair.h>

namespace LIEF::DEX::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, Object>(m, "Header", "DEX Header"_doc)

    .def_prop_ro("magic",
        nb::overload_cast<>(&Header::magic, nb::const_),
        "Magic value")

    .def_prop_ro("checksum",
        nb::overload_cast<>(&Header::checksum, nb::const_),
        "Checksum value of the rest of the file (without " RST_ATTR_REF(lief.DEX.Header.magic) ")"_doc)

    .def_prop_ro("signature",
        nb::overload_cast<>(&Header::signature, nb::const_),
        R"delim(
        SHA-1 signature of the rest of the file
        (without :attr:`~lief.DEX.Header.magic` and :attr:`~lief.DEX.Header.checksum`).
        )delim"_doc)

    .def_prop_ro("file_size",
        nb::overload_cast<>(&Header::file_size, nb::const_),
        "Size of the current DEX file"_doc)

    .def_prop_ro("header_size",
        nb::overload_cast<>(&Header::header_size, nb::const_),
        "Size of this header. Should be ``0x70``"_doc)

    .def_prop_ro("endian_tag",
        nb::overload_cast<>(&Header::endian_tag, nb::const_),
        "Endianness tag. Should be ``ENDIAN_CONSTANT``"_doc)

    .def_prop_ro("map_offset",
        nb::overload_cast<>(&Header::map, nb::const_),
        "Offset from the start of the file to the map item"_doc)

    .def_prop_ro("strings",
        nb::overload_cast<>(&Header::strings, nb::const_),
        "String identifiers"_doc)

    .def_prop_ro("link",
        nb::overload_cast<>(&Header::link, nb::const_),
        "Link (raw data)"_doc)

    .def_prop_ro("types",
        nb::overload_cast<>(&Header::types, nb::const_),
        "Type identifiers"_doc)

    .def_prop_ro("prototypes",
        nb::overload_cast<>(&Header::prototypes, nb::const_),
        "Prototypes identifiers"_doc)

    .def_prop_ro("fields", nb::overload_cast<>(&Header::fields, nb::const_),
        "Fields identifiers"_doc)

    .def_prop_ro("methods", nb::overload_cast<>(&Header::methods, nb::const_),
        "Methods identifiers"_doc)

    .def_prop_ro("classes", nb::overload_cast<>(&Header::classes, nb::const_),
        "Classess identifiers"_doc)

    .def_prop_ro("data", nb::overload_cast<>(&Header::data, nb::const_),
        "Raw data. Should be align on 32-bits"_doc)

    .def_prop_ro("nb_classes",
        nb::overload_cast<>(&Header::nb_classes, nb::const_),
        "Number of classes in the current DEX"_doc)

    .def_prop_ro("nb_methods",
        nb::overload_cast<>(&Header::nb_methods, nb::const_),
        "Number of methods in the current DEX"_doc)

    LIEF_DEFAULT_STR(Header);
}
}


