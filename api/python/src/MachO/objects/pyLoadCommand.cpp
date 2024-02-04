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
#include "nanobind/extra/memoryview.hpp"
#include "nanobind/utils.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

#include "MachO/pyMachO.hpp"


namespace LIEF::MachO::py {

template<>
void create<LoadCommand>(nb::module_& m) {

  nb::class_<LoadCommand, LIEF::Object>(m, "LoadCommand",
      "Based class for the Mach-O load commands"_doc)
    .def(nb::init<>())

    .def_prop_rw("command",
        nb::overload_cast<>(&LoadCommand::command, nb::const_),
        nb::overload_cast<LOAD_COMMAND_TYPES>(&LoadCommand::command),
        "Command type ( " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES) ")"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&LoadCommand::size, nb::const_),
        nb::overload_cast<uint32_t>(&LoadCommand::size),
        "Size of the command (should be greather than ``sizeof(load_command)``)"_doc)

    .def_prop_rw("data",
        [] (const LoadCommand& cmd) {
          return nb::to_memoryview(cmd.data());
        },
        nb::overload_cast<const LoadCommand::raw_t&>(&LoadCommand::data),
        "Command's data"_doc)

    .def_prop_rw("command_offset",
        nb::overload_cast<>(&LoadCommand::command_offset, nb::const_),
        nb::overload_cast<uint64_t>(&LoadCommand::command_offset),
        "Offset of the command within the *Load Command Table*"_doc)

    LIEF_DEFAULT_STR(LoadCommand);
}
}
