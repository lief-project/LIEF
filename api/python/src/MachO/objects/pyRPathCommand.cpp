/* Copyright 2017 - 2021 J.Rieck (based on R. Thomas's work)
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

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/RPathCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<RPathCommand>(nb::module_& m) {
  nb::class_<RPathCommand, LoadCommand>(m, "RPathCommand")

    .def_prop_rw("path",
        nb::overload_cast<>(&RPathCommand::path, nb::const_),
        nb::overload_cast<std::string>(&RPathCommand::path),
        "@rpath path"_doc, nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(RPathCommand);
}
}
