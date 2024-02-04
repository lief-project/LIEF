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
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>

#include "Abstract/init.hpp"
#include "pyLIEF.hpp"

#include "LIEF/Abstract/Header.hpp"

namespace LIEF::py {

template<>
void create<Header>(nb::module_& m) {
  nb::class_<Header, Object>(m, "Header",
     R"delim(
     Class which represents an abstracted Header
     )delim"_doc)
    .def(nb::init())
    .def_prop_rw("architecture",
        nb::overload_cast<>(&Header::architecture, nb::const_),
        nb::overload_cast<ARCHITECTURES>(&Header::architecture),
        "Target architecture (" RST_CLASS_REF(lief.ARCHITECTURES) ")"_doc)

    .def_prop_rw("modes",
        nb::overload_cast<>(&Header::modes, nb::const_),
        nb::overload_cast<const std::set<MODES>&>(&Header::modes),
        "Target " RST_CLASS_REF(lief.MODES) " (32-bits, 64-bits...)"_doc)

    .def_prop_rw("entrypoint",
        nb::overload_cast<>(&Header::entrypoint, nb::const_),
        nb::overload_cast<uint64_t>(&Header::entrypoint),
        "Binary entrypoint"_doc)

    .def_prop_rw("object_type",
        nb::overload_cast<>(&Header::object_type, nb::const_),
        nb::overload_cast<OBJECT_TYPES>(&Header::object_type),
        "Type of the binary (executable, library...)\n"
        "See: " RST_CLASS_REF(lief.OBJECT_TYPES) ""_doc)

    .def_prop_rw("endianness",
        nb::overload_cast<>(&Header::endianness, nb::const_),
        nb::overload_cast<ENDIANNESS>(&Header::endianness),
        "Binary endianness\n"
        "See: " RST_CLASS_REF(lief.ENDIANNESS) ""_doc)

    .def_prop_ro("is_32",
        &Header::is_32,
        "``True`` if the binary targets a ``32-bits`` architecture"_doc)

    .def_prop_ro("is_64",
        &Header::is_64,
        "``True`` if the binary targets a ``64-bits`` architecture"_doc)

    LIEF_DEFAULT_STR(Header);
}
}
