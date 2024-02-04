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

#include "LIEF/MachO/UUIDCommand.hpp"

#include "MachO/pyMachO.hpp"

#ifdef uuid_t
#pragma message("Windows #define uuid_t, undefine it for this file.")
#undef uuid_t
#endif

namespace LIEF::MachO::py {

template<>
void create<UUIDCommand>(nb::module_& m) {

  nb::class_<UUIDCommand, LoadCommand>(m, "UUIDCommand",
      "Class that represents the UUID command"_doc)

    .def_prop_rw("uuid",
        nb::overload_cast<>(&UUIDCommand::uuid, nb::const_),
        nb::overload_cast<const LIEF::MachO::uuid_t&>(&UUIDCommand::uuid),
        "UUID as a list"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(UUIDCommand);
}

}
