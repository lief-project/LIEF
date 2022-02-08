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

#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (DynamicEntryRpath::*)(void) const;

template<class T>
using setter_t = void (DynamicEntryRpath::*)(T);


template<>
void create<DynamicEntryRpath>(py::module& m) {
  py::class_<DynamicEntryRpath, DynamicEntry>(m, "DynamicEntryRpath",
      R"delim(
      Class which represents a ``DT_RPATH`` entry. This attribute is
      deprecated (cf. ``man ld``) in favour of ``DT_RUNPATH`` (See :class:`~lief.ELF.DynamicRunPath`)
      )delim")

    .def(py::init<const std::string &>(),
        "Constructor from (r)path",
        "path"_a = "")

    .def(py::init<const std::vector<std::string> &>(),
        "Constructor from a list of paths",
        "paths"_a)

    .def_property("name",
        [] (const DynamicEntryRpath& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryRpath::name),
        "The actual rpath as a string")

    .def_property("rpath",
        [] (const DynamicEntryRpath& obj) {
          return safe_string_converter(obj.rpath());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryRpath::rpath),
        "The actual rpath as a string")


    .def_property("paths",
        static_cast<getter_t<std::vector<std::string> >>(&DynamicEntryRpath::paths),
        static_cast<setter_t<const std::vector<std::string>&>>(&DynamicEntryRpath::paths),
        "Paths as a list")

    .def("insert",
        &DynamicEntryRpath::insert,
        "Insert a ``path`` at the given ``position``",
        "position"_a, "path"_a,
        py::return_value_policy::reference)

    .def("append",
        &DynamicEntryRpath::append,
        "Append the given ``path`` ",
        "path"_a,
        py::return_value_policy::reference)


    .def("remove",
        &DynamicEntryRpath::remove,
        "Remove the given ``path`` ",
        "path"_a,
        py::return_value_policy::reference)

    .def(py::self += std::string())
    .def(py::self -= std::string())

    .def("__eq__", &DynamicEntryRpath::operator==)
    .def("__ne__", &DynamicEntryRpath::operator!=)
    .def("__hash__",
        [] (const DynamicEntryRpath& entry) {
          return Hash::hash(entry);
        })


    .def("__str__",
        [] (const DynamicEntryRpath& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str =  stream.str();
          return str;
        });
}

}
}
