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
#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>
#include <nanobind/operators.h>

#include "LIEF/MachO/Header.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, LIEF::Object>(m, "Header",
      "Class that represents the Mach-O header"_doc)
    .def(nb::init<>())

    .def_prop_rw("magic",
        nb::overload_cast<>(&Header::magic, nb::const_),
        nb::overload_cast<MACHO_TYPES>(&Header::magic),
        R"delim(
        The Mach-O magic bytes. These bytes determine whether it is
        a 32 bits Mach-O, a 64 bits Mach-O files etc.
        )delim"_doc)

    .def_prop_rw("cpu_type",
        nb::overload_cast<>(&Header::cpu_type, nb::const_),
        nb::overload_cast<CPU_TYPES>(&Header::cpu_type),
        "Target CPU ( " RST_CLASS_REF(lief.MachO.CPU_TYPES) ")"_doc)

    .def_prop_rw("cpu_subtype",
        nb::overload_cast<>(&Header::cpu_subtype, nb::const_),
        nb::overload_cast<uint32_t>(&Header::cpu_subtype),
        R"delim(
        Return the CPU subtype supported by the Mach-O binary.
        For ARM architectures, this value could represent the minimum version
        for which the Mach-O binary has been compiled for.
        )delim"_doc)

    .def_prop_rw("file_type",
        nb::overload_cast<>(&Header::file_type, nb::const_),
        nb::overload_cast<FILE_TYPES>(&Header::file_type),
        "Binary's type ( " RST_CLASS_REF(lief.MachO.FILE_TYPES) ")"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&Header::flags, nb::const_),
        nb::overload_cast<uint32_t>(&Header::flags),
        "Binary's flags ( " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) ")"_doc)

    .def_prop_rw("nb_cmds",
        nb::overload_cast<>(&Header::nb_cmds, nb::const_),
        nb::overload_cast<uint32_t>(&Header::nb_cmds),
        "Number of " RST_CLASS_REF(lief.MachO.LoadCommand) ""_doc)

    .def_prop_rw("sizeof_cmds",
        nb::overload_cast<>(&Header::sizeof_cmds, nb::const_),
        nb::overload_cast<uint32_t>(&Header::sizeof_cmds),
        "Size of all " RST_CLASS_REF(lief.MachO.LoadCommand) ""_doc)

    .def_prop_rw("reserved",
        nb::overload_cast<>(&Header::reserved, nb::const_),
        nb::overload_cast<uint32_t>(&Header::reserved),
        "According to the official documentation, a reserved value"_doc)

    .def_prop_ro("flags_list",
        &Header::flags_list,
        "" RST_CLASS_REF(lief.PE.HEADER_FLAGS) " as a list"_doc)

    .def("add",
        nb::overload_cast<HEADER_FLAGS>(&Header::add),
        "Add the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) ""_doc,
        "flag"_a)

    .def("remove",
        nb::overload_cast<HEADER_FLAGS>(&Header::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) ""_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<HEADER_FLAGS>(&Header::has, nb::const_),
        "``True`` if the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) " is in the "
        ":attr:`~lief.MachO.Header.flags`"_doc,
        "flag"_a)

    .def(nb::self += HEADER_FLAGS(), nb::rv_policy::reference_internal)
    .def(nb::self -= HEADER_FLAGS(), nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<HEADER_FLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) " is present"_doc)

    LIEF_DEFAULT_STR(Header);
}
}
