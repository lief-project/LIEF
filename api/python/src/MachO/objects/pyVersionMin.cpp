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

#include "LIEF/MachO/VersionMin.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<VersionMin>(nb::module_& m) {

  nb::class_<VersionMin, LoadCommand>(m, "VersionMin",
      "Class that wraps the LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, ... commands"_doc)

    .def_prop_rw("version",
        nb::overload_cast<>(&VersionMin::version, nb::const_),
        nb::overload_cast<const VersionMin::version_t&>(&VersionMin::version),
        "Version as a tuple of **3** integers"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("sdk",
        nb::overload_cast<>(&VersionMin::sdk, nb::const_),
        nb::overload_cast<const VersionMin::version_t&>(&VersionMin::sdk),
        "SDK as a tuple of **3** integers"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(VersionMin);
}

}
