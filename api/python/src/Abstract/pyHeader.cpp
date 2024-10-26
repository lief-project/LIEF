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
#include <nanobind/stl/vector.h>

#include "Abstract/init.hpp"
#include "pyLIEF.hpp"

#include "LIEF/Abstract/Header.hpp"
#include "enums_wrapper.hpp"

namespace LIEF::py {

template<>
void create<Header>(nb::module_& m) {
  nb::class_<Header, Object> obj(m, "Header",
     R"delim(
     Class which represents an abstracted Header
     )delim"_doc);

  #define ENTRY(X) .value(to_string(Header::ARCHITECTURES::X), Header::ARCHITECTURES::X)
  enum_<Header::ARCHITECTURES>(obj, "ARCHITECTURES")
    ENTRY(UNKNOWN)
    ENTRY(ARM)
    ENTRY(ARM64)
    ENTRY(MIPS)
    ENTRY(X86)
    ENTRY(X86_64)
    ENTRY(PPC)
    ENTRY(SPARC)
    ENTRY(SYSZ)
    ENTRY(XCORE)
    ENTRY(RISCV)
    ENTRY(LOONGARCH)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Header::ENDIANNESS::X), Header::ENDIANNESS::X)
  enum_<Header::ENDIANNESS>(obj, "ENDIANNESS")
    ENTRY(UNKNOWN)
    ENTRY(BIG)
    ENTRY(LITTLE)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Header::MODES::X), Header::MODES::X)
  enum_<Header::MODES>(obj, "MODES")
    ENTRY(NONE)
    ENTRY(BITS_16)
    ENTRY(BITS_32)
    ENTRY(BITS_64)
    ENTRY(THUMB)
    ENTRY(ARM64E)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Header::OBJECT_TYPES::X), Header::OBJECT_TYPES::X)
  enum_<Header::OBJECT_TYPES>(obj, "OBJECT_TYPES")
    ENTRY(UNKNOWN)
    ENTRY(EXECUTABLE)
    ENTRY(LIBRARY)
    ENTRY(OBJECT)
  ;
  #undef ENTRY

  obj
    .def_prop_ro("architecture",
        nb::overload_cast<>(&Header::architecture, nb::const_),
        "Target architecture"_doc)

    .def_prop_ro("modes",
        nb::overload_cast<>(&Header::modes, nb::const_),
        "Architecture details"_doc)

    .def_prop_ro("modes_list",
        nb::overload_cast<>(&Header::modes_list, nb::const_),
        "*Modes* as a list"_doc)

    .def_prop_ro("entrypoint",
        nb::overload_cast<>(&Header::entrypoint, nb::const_),
        "Binary entrypoint"_doc)

    .def_prop_ro("object_type",
        nb::overload_cast<>(&Header::object_type, nb::const_),
        "Type of the binary (executable, library...)"_doc)

    .def_prop_ro("endianness",
        nb::overload_cast<>(&Header::endianness, nb::const_),
        "Binary endianness"_doc)

    .def_prop_ro("is_32",
        &Header::is_32,
        "``True`` if the binary targets a ``32-bits`` architecture"_doc)

    .def_prop_ro("is_64",
        &Header::is_64,
        "``True`` if the binary targets a ``64-bits`` architecture"_doc)

    LIEF_DEFAULT_STR(Header);
}
}
