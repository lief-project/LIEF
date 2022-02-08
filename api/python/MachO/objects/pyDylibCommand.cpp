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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DylibCommand.hpp"

#include "pyMachO.hpp"


namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DylibCommand::*)(void) const;

template<class T>
using setter_t = void (DylibCommand::*)(T);


template<>
void create<DylibCommand>(py::module& m) {

  py::class_<DylibCommand, LoadCommand>(m, "DylibCommand",
      R"delim(
      Class which represents a library dependency
      )delim")

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&DylibCommand::name),
        static_cast<setter_t<const std::string&>>(&DylibCommand::name),
        "Library's name",
        py::return_value_policy::reference_internal)

    .def_property("timestamp",
        static_cast<getter_t<uint32_t>>(&DylibCommand::timestamp),
        static_cast<setter_t<uint32_t>>(&DylibCommand::timestamp),
        "Library's timestamp",
        py::return_value_policy::reference_internal)

    .def_property("current_version",
        static_cast<getter_t<DylibCommand::version_t>>(&DylibCommand::current_version),
        static_cast<setter_t<DylibCommand::version_t>>(&DylibCommand::current_version),
        "Library's current version",
        py::return_value_policy::reference_internal)

    .def_property("compatibility_version",
        static_cast<getter_t<DylibCommand::version_t>>(&DylibCommand::compatibility_version),
        static_cast<setter_t<DylibCommand::version_t>>(&DylibCommand::compatibility_version),
        "Library's compatibility version",
        py::return_value_policy::reference_internal)

    .def_static("weak_lib",
        &DylibCommand::weak_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES.LOAD_WEAK_DYLIB) " library",
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("id_dylib",
        &DylibCommand::id_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB) " library",
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("load_dylib",
        &DylibCommand::load_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES.LOAD_DYLIB) " library",
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("reexport_dylib",
        &DylibCommand::reexport_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES.REEXPORT_DYLIB) " library",
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("load_upward_dylib",
        &DylibCommand::load_upward_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES.LOAD_UPWARD_DYLIB) " library",
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def_static("lazy_load_dylib",
        &DylibCommand::lazy_load_dylib,
        "Factory function to generate a " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES.LAZY_LOAD_DYLIB) " library",
        "name"_a, "timestamp"_a = 0, "current_version"_a = 0, "compat_version"_a = 0)

    .def("__eq__", &DylibCommand::operator==)
    .def("__ne__", &DylibCommand::operator!=)
    .def("__hash__",
        [] (const DylibCommand& dylib_command) {
          return Hash::hash(dylib_command);
        })


    .def("__str__",
        [] (const DylibCommand& command)
        {
          std::ostringstream stream;
          stream << command;
          std::string str = stream.str();
          return str;
        });

}

}
}
