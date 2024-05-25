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

#include "LIEF/MachO/UnknownCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<UnknownCommand>(nb::module_& m) {

  nb::class_<UnknownCommand, LoadCommand>(m, "UnknownCommand",
      "Generic class when the command is not recognized by LIEF"_doc)

    .def_prop_ro("original_command",
        nb::overload_cast<>(&UnknownCommand::original_command, nb::const_))

    LIEF_DEFAULT_STR(UnknownCommand);
}

}
