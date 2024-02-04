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

#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryRunPath>(nb::module_& m) {
  nb::class_<DynamicEntryRunPath, DynamicEntry>(m, "DynamicEntryRunPath",
      R"delim(
      Class that represents a ``DT_RUNPATH`` wich is used by the loader
      to resolve libraries (:class:`~lief.ELF.DynamicEntryLibrary`).
      )delim"_doc)

    .def(nb::init<const std::string &>(),
        "Constructor from a (run)path"_doc,
        "path"_a = "")

    .def(nb::init<const std::vector<std::string> &>(),
        "Constructor from a list of paths"_doc,
        "paths"_a)

    .def_prop_rw("runpath",
        [] (const DynamicEntryRunPath& obj) {
          return LIEF::py::safe_string(obj.runpath());
        },
        nb::overload_cast<std::string>(&DynamicEntryRunPath::runpath),
        "Runpath raw value"_doc)

    .def_prop_rw("paths",
        nb::overload_cast<>(&DynamicEntryRunPath::paths, nb::const_),
        nb::overload_cast<const std::vector<std::string>&>(&DynamicEntryRunPath::paths),
        "Paths as a list"_doc)

    .def("insert", &DynamicEntryRunPath::insert,
        "Insert a ``path`` at the given ``position``"_doc,
        "position"_a, "path"_a,
        nb::rv_policy::reference_internal)

    .def("append", &DynamicEntryRunPath::append,
        "Append the given ``path`` "_doc,
        "path"_a, nb::rv_policy::reference_internal)

    .def("remove", &DynamicEntryRunPath::remove,
        "Remove the given ``path`` ",
        "path"_a,
        nb::rv_policy::reference_internal)

    .def(nb::self += std::string())
    .def(nb::self -= std::string())

    LIEF_DEFAULT_STR(DynamicEntryRunPath);
}

}
