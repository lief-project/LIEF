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
#include "enums_wrapper.hpp"

#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryFlags>(nb::module_& m) {
  nb::class_<DynamicEntryFlags, DynamicEntry> entry(m, "DynamicEntryFlags");

  #define ENTRY(X) .value(to_string(DynamicEntryFlags::FLAG::X), DynamicEntryFlags::FLAG::X)
  enum_<DynamicEntryFlags::FLAG>(entry, "FLAG")
    ENTRY(ORIGIN)
    ENTRY(SYMBOLIC)
    ENTRY(TEXTREL)
    ENTRY(BIND_NOW)
    ENTRY(STATIC_TLS)
    ENTRY(NOW)
    ENTRY(GLOBAL)
    ENTRY(GROUP)
    ENTRY(NODELETE)
    ENTRY(LOADFLTR)
    ENTRY(INITFIRST)
    ENTRY(NOOPEN)
    ENTRY(HANDLE_ORIGIN)
    ENTRY(DIRECT)
    ENTRY(TRANS)
    ENTRY(INTERPOSE)
    ENTRY(NODEFLIB)
    ENTRY(NODUMP)
    ENTRY(CONFALT)
    ENTRY(ENDFILTEE)
    ENTRY(DISPRELDNE)
    ENTRY(DISPRELPND)
    ENTRY(NODIRECT)
    ENTRY(IGNMULDEF)
    ENTRY(NOKSYMS)
    ENTRY(NOHDR)
    ENTRY(EDITED)
    ENTRY(NORELOC)
    ENTRY(SYMINTPOSE)
    ENTRY(GLOBAUDIT)
    ENTRY(SINGLETON)
    ENTRY(PIE)
    ENTRY(KMOD)
    ENTRY(WEAKFILTER)
    ENTRY(NOCOMMON)
  ;
  #undef ENTRY

  entry
    .def_prop_ro("flags",
        &DynamicEntryFlags::flags,
        "Return list of :class:`~.FLAG`"_doc,
        nb::rv_policy::move)

    .def("has",
        nb::overload_cast<DynamicEntryFlags::FLAG>(&DynamicEntryFlags::has, nb::const_),
        "Check if this entry contains the given :class:`~.FLAG`"_doc,
        "flag"_a)


    .def("add",
        nb::overload_cast<DynamicEntryFlags::FLAG>(&DynamicEntryFlags::add),
        "Add the given :class:`~.FLAG`"_doc,
        "flag"_a)

    .def("remove",
        nb::overload_cast<DynamicEntryFlags::FLAG>(&DynamicEntryFlags::remove),
        "Remove the given :class:`~.FLAG`"_doc,
        "flag"_a)

    .def(nb::self += DynamicEntryFlags::FLAG())
    .def(nb::self -= DynamicEntryFlags::FLAG())

    .def("__contains__",
        nb::overload_cast<DynamicEntryFlags::FLAG>(&DynamicEntryFlags::has, nb::const_),
        "Check if the given :class:`~.FLAG` is present"_doc)

    LIEF_DEFAULT_STR(DynamicEntryFlags);
}

}
