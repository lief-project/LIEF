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

#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (DynamicEntryFlags::*)(void) const;

template<class T>
using setter_t = void (DynamicEntryFlags::*)(T);


template<>
void create<DynamicEntryFlags>(py::module& m) {

  py::class_<DynamicEntryFlags, DynamicEntry>(m, "DynamicEntryFlags")
    .def(py::init<>())

    .def(py::init<DYNAMIC_TAGS, uint64_t>(),
        "Constructor with " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " and value",
        "tag"_a, "value"_a)

    .def_property_readonly("flags",
        &DynamicEntryFlags::flags,
        "Return list of " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) " or " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) " (integer)",
        py::return_value_policy::move)

    .def("has",
        static_cast<bool (DynamicEntryFlags::*)(DYNAMIC_FLAGS) const>(&DynamicEntryFlags::has),
        "Check if this entry contains the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) "",
        "flag"_a)

    .def("has",
        static_cast<bool (DynamicEntryFlags::*)(DYNAMIC_FLAGS_1) const>(&DynamicEntryFlags::has),
        "Check if this entry contains the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) "",
        "flag"_a)

    .def("add",
        static_cast<void (DynamicEntryFlags::*)(DYNAMIC_FLAGS)>(&DynamicEntryFlags::add),
        "Add the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) "",
        "flag"_a)

    .def("add",
        static_cast<void (DynamicEntryFlags::*)(DYNAMIC_FLAGS_1)>(&DynamicEntryFlags::add),
        "Add the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) "",
        "flag"_a)

    .def("remove",
        static_cast<void (DynamicEntryFlags::*)(DYNAMIC_FLAGS)>(&DynamicEntryFlags::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) "",
        "flag"_a)

    .def("remove",
        static_cast<void (DynamicEntryFlags::*)(DYNAMIC_FLAGS_1)>(&DynamicEntryFlags::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) "",
        "flag"_a)


    .def("__eq__", &DynamicEntryFlags::operator==)
    .def("__ne__", &DynamicEntryFlags::operator!=)
    .def("__hash__",
        [] (const DynamicEntryFlags& entry) {
          return Hash::hash(entry);
        })

    .def(py::self += DYNAMIC_FLAGS())
    .def(py::self += DYNAMIC_FLAGS_1())


    .def(py::self -= DYNAMIC_FLAGS())
    .def(py::self -= DYNAMIC_FLAGS_1())

    .def("__contains__",
        static_cast<bool (DynamicEntryFlags::*)(DYNAMIC_FLAGS) const>(&DynamicEntryFlags::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) " is present")

    .def("__contains__",
        static_cast<bool (DynamicEntryFlags::*)(DYNAMIC_FLAGS_1) const>(&DynamicEntryFlags::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) " is present")


    .def("__str__",
        [] (const DynamicEntryFlags& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str =  stream.str();
          return str;
        });
}

}
}
