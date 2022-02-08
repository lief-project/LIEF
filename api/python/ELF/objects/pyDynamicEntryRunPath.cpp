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
#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (DynamicEntryRunPath::*)(void) const;

template<class T>
using setter_t = void (DynamicEntryRunPath::*)(T);


template<>
void create<DynamicEntryRunPath>(py::module& m) {

  py::class_<DynamicEntryRunPath, DynamicEntry>(m, "DynamicEntryRunPath",
      R"delim(
      Class that represents a ``DT_RUNPATH`` wich is used by the loader
      to resolve libraries (:class:`~lief.ELF.DynamicEntryLibrary`).
      )delim")

    .def(py::init<const std::string &>(),
        "Constructor from a (run)path",
        "path"_a = "")

    .def(py::init<const std::vector<std::string> &>(),
        "Constructor from a list of paths",
        "paths"_a)

    .def_property("name",
        [] (const DynamicEntryRunPath& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryRunPath::name),
        "Runpath raw value")

    .def_property("runpath",
        [] (const DynamicEntryRunPath& obj) {
          return safe_string_converter(obj.runpath());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryRunPath::runpath),
        "Runpath raw value")

    .def_property("paths",
        static_cast<getter_t<std::vector<std::string> >>(&DynamicEntryRunPath::paths),
        static_cast<setter_t<const std::vector<std::string>&>>(&DynamicEntryRunPath::paths),
        "Paths as a list")

    .def("insert",
        &DynamicEntryRunPath::insert,
        "Insert a ``path`` at the given ``position``",
        "position"_a, "path"_a,
        py::return_value_policy::reference)

    .def("append",
        &DynamicEntryRunPath::append,
        "Append the given ``path`` ",
        "path"_a,
        py::return_value_policy::reference)


    .def("remove",
        &DynamicEntryRunPath::remove,
        "Remove the given ``path`` ",
        "path"_a,
        py::return_value_policy::reference)


    .def(py::self += std::string())
    .def(py::self -= std::string())

    .def("__eq__", &DynamicEntryRunPath::operator==)
    .def("__ne__", &DynamicEntryRunPath::operator!=)
    .def("__hash__",
        [] (const DynamicEntryRunPath& entry) {
          return Hash::hash(entry);
        })

    .def("__str__",
        [] (const DynamicEntryRunPath& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str = stream.str();
          return str;
        });
}

}
}
