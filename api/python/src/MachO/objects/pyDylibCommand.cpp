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
#include <nanobind/stl/array.h>

#include "LIEF/MachO/DylibCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {
template<>
void create<DylibCommand>(nb::module_& m) {
  nb::class_<DylibCommand, LoadCommand>(m, "DylibCommand",
      R"delim(Class which represents a library dependency)delim"_doc)

    .def_prop_rw("name",
        nb::overload_cast<>(&DylibCommand::name, nb::const_),
        nb::overload_cast<std::string>(&DylibCommand::name),
        "Library's name"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("timestamp",
        nb::overload_cast<>(&DylibCommand::timestamp, nb::const_),
        nb::overload_cast<uint32_t>(&DylibCommand::timestamp),
        "Library's timestamp"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("current_version",
        nb::overload_cast<>(&DylibCommand::current_version, nb::const_),
        nb::overload_cast<DylibCommand::version_t>(&DylibCommand::current_version),
        "Library's current version"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("compatibility_version",
        nb::overload_cast<>(&DylibCommand::compatibility_version, nb::const_),
        nb::overload_cast<DylibCommand::version_t>(&DylibCommand::compatibility_version),
        "Library's compatibility version"_doc,
        nb::rv_policy::reference_internal)

    .def_static("weak_lib",
        &DylibCommand::weak_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LoadCommand.TYPE.LOAD_WEAK_DYLIB) " library"_doc,
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("id_dylib",
        &DylibCommand::id_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LoadCommand.TYPE.ID_DYLIB) " library"_doc,
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("load_dylib",
        &DylibCommand::load_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LoadCommand.TYPE.LOAD_DYLIB) " library"_doc,
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("reexport_dylib",
        &DylibCommand::reexport_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LoadCommand.TYPE.REEXPORT_DYLIB) " library"_doc,
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("load_upward_dylib",
        &DylibCommand::load_upward_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LoadCommand.TYPE.LOAD_UPWARD_DYLIB) " library"_doc,
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("lazy_load_dylib",
        &DylibCommand::lazy_load_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LoadCommand.TYPE.LAZY_LOAD_DYLIB) " library"_doc,
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    LIEF_DEFAULT_STR(DylibCommand);
}

}
