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

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (DynamicEntryLibrary::*)(void) const;

template<class T>
using setter_t = void (DynamicEntryLibrary::*)(T);

void init_ELF_DynamicEntryLibrary_class(py::module& m) {

  //
  // Dynamic Entry Library object
  //
  py::class_<DynamicEntryLibrary, DynamicEntry>(m, "DynamicEntryLibrary")
    .def(py::init<const std::string &>(),
        "Constructor from library name",
        "library_name"_a)

    .def_property("name",
        [] (const DynamicEntryLibrary& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&DynamicEntryLibrary::name),
        "Return library's name")

    .def("__eq__", &DynamicEntryLibrary::operator==)
    .def("__ne__", &DynamicEntryLibrary::operator!=)
    .def("__hash__",
        [] (const DynamicEntryLibrary& entry) {
          return Hash::hash(entry);
        })


    .def("__str__",
        [] (const DynamicEntryLibrary& dynamicEntryLibrary)
        {
          std::ostringstream stream;
          stream << dynamicEntryLibrary;
          std::string str =  stream.str();
          return str;
        });
}
