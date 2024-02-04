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

#include "LIEF/MachO/MainCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<MainCommand>(nb::module_& m) {

  nb::class_<MainCommand, LoadCommand>(m, "MainCommand",
      R"delim(
      Class that represent the LC_MAIN command. This kind
      of command can be used to determine the entrypoint of an executable
      )delim"_doc)
    .def(nb::init<uint64_t, uint64_t>())

    .def_prop_rw("entrypoint",
        nb::overload_cast<>(&MainCommand::entrypoint, nb::const_),
        nb::overload_cast<uint64_t>(&MainCommand::entrypoint),
        "Offset of the *main* function relative to the ``__TEXT`` segment"_doc)

    .def_prop_rw("stack_size",
        nb::overload_cast<>(&MainCommand::stack_size, nb::const_),
        nb::overload_cast<uint64_t>(&MainCommand::stack_size),
        "The initial stack size (if not 0)"_doc)

    LIEF_DEFAULT_STR(MainCommand);

}
}
