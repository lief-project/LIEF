/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/Section.hpp"

#include "PE/pyPE.hpp"

namespace LIEF::PE::py {

template<>
void create<DataDirectory>(nb::module_& m) {
  nb::class_<DataDirectory, LIEF::Object>(m, "DataDirectory",
      R"delim(
      Class that represents a PE data directory entry
      )delim"_doc)
    .def(nb::init<>())
    .def_prop_rw("rva",
        nb::overload_cast<>(&DataDirectory::RVA, nb::const_),
        nb::overload_cast<uint32_t>(&DataDirectory::RVA),
        "**Relative** virtual address of the content associated with the current data directory"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&DataDirectory::size, nb::const_),
        nb::overload_cast<uint32_t>(&DataDirectory::size),
        "Size in bytes of the content associated with the current data directory"_doc)

    .def_prop_ro("section",
        nb::overload_cast<>(&DataDirectory::section),
        "" RST_CLASS_REF(lief.PE.Section) " associated with the current data directory or None if not linked"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("type",
        &DataDirectory::type,
        "Type (" RST_CLASS_REF(lief.PE.DATA_DIRECTORY) ") of the current data directory"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_section",
        &DataDirectory::has_section,
        "``True`` if the current data directory is tied to a " RST_CLASS_REF(lief.PE.Section) ""_doc)

    LIEF_DEFAULT_STR(LIEF::PE::DataDirectory);
}
}
