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
#include <nanobind/stl/array.h>
#include <nanobind/stl/vector.h>

#include "LIEF/MachO/BuildVersion.hpp"
#include "LIEF/MachO/EnumToString.hpp"

#include "enums_wrapper.hpp"

#include "MachO/pyMachO.hpp"

#define PY_ENUM(x) LIEF::MachO::to_string(x), x

namespace LIEF::MachO::py {
template<>
void create<BuildVersion>(nb::module_& m) {

  nb::class_<BuildVersion, LoadCommand> cls(m, "BuildVersion");
  nb::class_<BuildToolVersion, Object> tool_version_cls(m, "BuildToolVersion",
      R"delim(
      Class that represents a tool's version that was involved in the build
      of the binary
      )delim"_doc);

  // Build Tool Version
  // ==================
  tool_version_cls
    .def_prop_ro("tool",
        &BuildToolVersion::tool,
        "" RST_CLASS_REF(.BuildVersion.TOOLS) " type"_doc)

    .def_prop_ro("version",
        &BuildToolVersion::version,
        "Version of the tool"_doc)

    LIEF_DEFAULT_STR(BuildToolVersion);

  LIEF::enum_<BuildToolVersion::TOOLS>(tool_version_cls, "TOOLS")
    .value(PY_ENUM(BuildToolVersion::TOOLS::UNKNOWN))
    .value(PY_ENUM(BuildToolVersion::TOOLS::CLANG))
    .value(PY_ENUM(BuildToolVersion::TOOLS::SWIFT))
    .value(PY_ENUM(BuildToolVersion::TOOLS::LD));

  cls
    .def_prop_rw("platform",
        nb::overload_cast<>(&BuildVersion::platform, nb::const_),
        nb::overload_cast<BuildVersion::PLATFORMS>(&BuildVersion::platform),
        "Target " RST_CLASS_REF(.BuildVersion.PLATFORMS) ""_doc)

    .def_prop_rw("minos",
        nb::overload_cast<>(&BuildVersion::minos, nb::const_),
        nb::overload_cast<BuildVersion::version_t>(&BuildVersion::minos),
        "Minimal OS version on which this binary was built to run"_doc)

    .def_prop_rw("sdk",
        nb::overload_cast<>(&BuildVersion::sdk, nb::const_),
        nb::overload_cast<BuildVersion::version_t>(&BuildVersion::sdk),
        "SDK Version"_doc)

    .def_prop_ro("tools",
        nb::overload_cast<>(&BuildVersion::tools, nb::const_),
        "List of " RST_CLASS_REF(BuildToolVersion) " used when while this binary"_doc)

    LIEF_DEFAULT_STR(BuildVersion);


  enum_<BuildVersion::PLATFORMS>(cls, "PLATFORMS")
    .value(PY_ENUM(BuildVersion::PLATFORMS::UNKNOWN))
    .value(PY_ENUM(BuildVersion::PLATFORMS::MACOS))
    .value(PY_ENUM(BuildVersion::PLATFORMS::IOS))
    .value(PY_ENUM(BuildVersion::PLATFORMS::TVOS))
    .value(PY_ENUM(BuildVersion::PLATFORMS::WATCHOS));

}

}
