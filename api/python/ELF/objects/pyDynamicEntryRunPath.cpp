/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (DynamicEntryRunPath::*)(void) const;

template<class T>
using setter_t = void (DynamicEntryRunPath::*)(T);

void init_ELF_DynamicEntryRunPath_class(py::module& m) {

  //
  // Dynamic Entry RUNPATH object
  //
  py::class_<DynamicEntryRunPath, DynamicEntry>(m, "DynamicEntryRunPath")
    .def(py::init<const std::string &>())
    .def_property("name",
        [] (const DynamicEntryRunPath& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryRunPath::name),
        "Return path value")

    .def_property("runpath",
        [] (const DynamicEntryRunPath& obj) {
          return safe_string_converter(obj.runpath());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryRunPath::runpath),
        "Return path value")

    .def("__eq__", &DynamicEntryRunPath::operator==)
    .def("__ne__", &DynamicEntryRunPath::operator!=)
    .def("__hash__",
        [] (const DynamicEntryRunPath& entry) {
          return LIEF::Hash::hash(entry);
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
