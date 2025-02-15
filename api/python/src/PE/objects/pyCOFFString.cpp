/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "PE/pyPE.hpp"

#include "LIEF/PE/COFFString.hpp"

#include <sstream>
#include <string>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<COFFString>(nb::module_& m) {
  nb::class_<COFFString>(m, "COFFString",
    R"doc(
    This class represents a string located in the COFF string table.

    Some of these strings can be used for section's name where its lenght is greater than 8
    bytes. See: :attr:`~.Section.coff_string`.

    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-string-table
    )doc"_doc
  )

    .def_prop_rw("string", nb::overload_cast<>(&COFFString::str, nb::const_),
                 nb::overload_cast<std::string>(&COFFString::str),
                 nb::rv_policy::reference_internal,
                 "The actual string"_doc)

    .def_prop_rw("offset", nb::overload_cast<>(&COFFString::offset, nb::const_),
                 nb::overload_cast<uint32_t>(&COFFString::offset),
                 nb::rv_policy::reference_internal,
      R"doc(
      The offset of this string the in the COFF string table.
      This offset includes the first 4-bytes that holds the table size
      )doc"_doc)

  LIEF_DEFAULT_STR(COFFString);
}

}

