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

#include <nanobind/operators.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryFlags>(nb::module_& m) {
  nb::class_<DynamicEntryFlags, DynamicEntry>(m, "DynamicEntryFlags")
    .def(nb::init<>())

    .def(nb::init<DYNAMIC_TAGS, uint64_t>(),
        "Constructor with " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " and value"_doc,
        "tag"_a, "value"_a)

    .def_prop_ro("flags",
        &DynamicEntryFlags::flags,
        "Return list of " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) " or " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) " (integer)"_doc,
        nb::rv_policy::move)

    .def("has",
        nb::overload_cast<DYNAMIC_FLAGS>(&DynamicEntryFlags::has, nb::const_),
        "Check if this entry contains the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) ""_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<DYNAMIC_FLAGS_1>(&DynamicEntryFlags::has, nb::const_),
        "Check if this entry contains the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) ""_doc,
        "flag"_a)

    .def("add",
        nb::overload_cast<DYNAMIC_FLAGS>(&DynamicEntryFlags::add),
        "Add the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) ""_doc,
        "flag"_a)

    .def("add",
        nb::overload_cast<DYNAMIC_FLAGS_1>(&DynamicEntryFlags::add),
        "Add the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) ""_doc,
        "flag"_a)

    .def("remove",
        nb::overload_cast<DYNAMIC_FLAGS>(&DynamicEntryFlags::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) ""_doc,
        "flag"_a)

    .def("remove",
        nb::overload_cast<DYNAMIC_FLAGS_1>(&DynamicEntryFlags::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) ""_doc,
        "flag"_a)

    .def(nb::self += DYNAMIC_FLAGS())
    .def(nb::self += DYNAMIC_FLAGS_1())

    .def(nb::self -= DYNAMIC_FLAGS())
    .def(nb::self -= DYNAMIC_FLAGS_1())

    .def("__contains__",
        nb::overload_cast<DYNAMIC_FLAGS>(&DynamicEntryFlags::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS) " is present"_doc)

    .def("__contains__",
        nb::overload_cast<DYNAMIC_FLAGS_1>(&DynamicEntryFlags::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.DYNAMIC_FLAGS_1) " is present"_doc)

    LIEF_DEFAULT_STR(DynamicEntryFlags);
}

}
