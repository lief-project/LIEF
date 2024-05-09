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
#include <algorithm>

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/MachO/DyldEnvironment.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<DyldEnvironment>(nb::module_& m) {

  nb::class_<DyldEnvironment, LoadCommand>(m, "DyldEnvironment",
      R"delim(
      Class that represents a LC_DYLD_ENVIRONMENT which is
      used by the Mach-O linker/loader to initialize an environment variable
      )delim"_doc)

    .def_prop_rw("value",
        nb::overload_cast<>(&DyldEnvironment::value, nb::const_),
        nb::overload_cast<std::string>(&DyldEnvironment::value),
        "Environment variable as a string"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(DyldEnvironment);
}
}
