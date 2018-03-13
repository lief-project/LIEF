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

#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/hash.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (DynamicEntry::*)(void) const;

template<class T>
using setter_t = void (DynamicEntry::*)(T);

void init_ELF_DynamicEntry_class(py::module& m) {

  // DynamicEntry object
  py::class_<DynamicEntry, LIEF::Object>(m, "DynamicEntry")
    .def(py::init<>(),
        "Default constructor")

    .def(py::init<DYNAMIC_TAGS, uint64_t>(),
        "Constructor with " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " and value",
        "tag"_a, "value"_a)

    .def_property("tag",
        static_cast<getter_t<DYNAMIC_TAGS>>(&DynamicEntry::tag),
        static_cast<setter_t<DYNAMIC_TAGS>>(&DynamicEntry::tag),
        "Return the entry's " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " which represent the entry type")

    .def_property("value",
        static_cast<getter_t<uint64_t>>(&DynamicEntry::value),
        static_cast<setter_t<uint64_t>>(&DynamicEntry::value),
        "Return the entry's value.")

    .def("__eq__", &DynamicEntry::operator==)
    .def("__ne__", &DynamicEntry::operator!=)
    .def("__hash__",
        [] (const DynamicEntry& entry) {
          return Hash::hash(entry);
        })

    .def("__str__",
        [] (const DynamicEntry& dynamicEntry)
        {
          std::ostringstream stream;
          stream << dynamicEntry;
          std::string str =  stream.str();
          return str;
        });
}
