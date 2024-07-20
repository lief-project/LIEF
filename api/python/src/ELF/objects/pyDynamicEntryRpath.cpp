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
#include <string>
#include <sstream>

#include <nanobind/operators.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "ELF/pyELF.hpp"
#include "pySafeString.hpp"

#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryRpath>(nb::module_& m) {
  nb::class_<DynamicEntryRpath, DynamicEntry>(m, "DynamicEntryRpath",
      R"delim(
      Class which represents a ``DT_RPATH`` entry. This attribute is
      deprecated (cf. ``man ld``) in favour of ``DT_RUNPATH`` (See :class:`~lief.ELF.DynamicRunPath`)
      )delim"_doc)

    .def(nb::init<const std::string &>(),
        "Constructor from (r)path"_doc,
        "path"_a = "")

    .def(nb::init<const std::vector<std::string> &>(),
        "Constructor from a list of paths"_doc,
        "paths"_a)

    .def_prop_rw("rpath",
        [] (const DynamicEntryRpath& obj) {
          return LIEF::py::safe_string(obj.rpath());
        },
        nb::overload_cast<std::string>(&DynamicEntryRpath::rpath),
        "The actual rpath as a string"_doc)

    .def_prop_rw("paths",
        nb::overload_cast<>(&DynamicEntryRpath::paths, nb::const_),
        nb::overload_cast<const std::vector<std::string>&>(&DynamicEntryRpath::paths),
        "Paths as a list"_doc)

    .def("insert", &DynamicEntryRpath::insert,
        "Insert a ``path`` at the given ``position``"_doc,
        "position"_a, "path"_a,
        nb::rv_policy::reference_internal)

    .def("append", &DynamicEntryRpath::append,
        "Append the given ``path`` "_doc,
        "path"_a,
        nb::rv_policy::reference_internal)

    .def("remove", &DynamicEntryRpath::remove,
        "Remove the given ``path`` "_doc,
        "path"_a,
        nb::rv_policy::reference_internal)

    .def(nb::self += std::string())
    .def(nb::self -= std::string())

    LIEF_DEFAULT_STR(DynamicEntryRpath);
}

}
