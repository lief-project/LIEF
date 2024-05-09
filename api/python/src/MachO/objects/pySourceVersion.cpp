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

#include "LIEF/MachO/SourceVersion.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<SourceVersion>(nb::module_& m) {

  nb::class_<SourceVersion, LoadCommand>(m, "SourceVersion",
      R"delim(
      Class that represents the MachO :attr:`~.LoadCommand.TYPE.SOURCE_VERSION`
      This command is used to provide the *version* of the sources used to build the binary
      )delim"_doc)

    .def_prop_rw("version",
        nb::overload_cast<>(&SourceVersion::version, nb::const_),
        nb::overload_cast<const SourceVersion::version_t&>(&SourceVersion::version),
        "Version as a tuple of **5** integers"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(SourceVersion);
}

}
