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

#include "LIEF/MachO/DylinkerCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<DylinkerCommand>(nb::module_& m) {

  nb::class_<DylinkerCommand, LoadCommand>(m, "DylinkerCommand",
      R"delim(
      Class that represents the Mach-O linker, also named loader
      Most of the time, :attr:`~lief.MachO.DylinkerCommand.name` returns ``/usr/lib/dyld``
      )delim"_doc)
    .def(nb::init<const std::string&>())

    .def_prop_rw("name",
        nb::overload_cast<>(&DylinkerCommand::name, nb::const_),
        nb::overload_cast<std::string>(&DylinkerCommand::name),
        "Path to the loader/linker"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(DylinkerCommand);
}
}
