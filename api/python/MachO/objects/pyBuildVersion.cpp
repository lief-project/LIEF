/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/BuildVersion.hpp"
#include "LIEF/MachO/EnumToString.hpp"

#include "enums_wrapper.hpp"

#include "pyMachO.hpp"

#define PY_ENUM(x) LIEF::MachO::to_string(x), x

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (BuildVersion::*)(void) const;

template<class T>
using setter_t = void (BuildVersion::*)(T);


template<>
void create<BuildVersion>(py::module& m) {

  py::class_<BuildVersion, LoadCommand> cls(m, "BuildVersion");
  py::class_<BuildToolVersion, LIEF::Object> tool_version_cls(m, "BuildToolVersion",
      R"delim(
      Class that represents a tool's version that was involved in the build of the binary
      )delim");


  // Build Tool Version
  // ==================
  tool_version_cls
    .def_property_readonly("tool",
        &BuildToolVersion::tool,
        "" RST_CLASS_REF(.BuildVersion.TOOLS) " type")

    .def_property_readonly("version",
        &BuildToolVersion::version,
        "Version of the tool")

    .def("__eq__", &BuildToolVersion::operator==)
    .def("__ne__", &BuildToolVersion::operator!=)
    .def("__hash__",
        [] (const BuildToolVersion& version) {
          return Hash::hash(version);
        })

    .def("__str__",
        [] (const BuildToolVersion& version)
        {
          std::ostringstream stream;
          stream << version;
          return stream.str();
        });


  LIEF::enum_<BuildToolVersion::TOOLS>(tool_version_cls, "TOOLS")
    .value(PY_ENUM(BuildToolVersion::TOOLS::UNKNOWN))
    .value(PY_ENUM(BuildToolVersion::TOOLS::CLANG))
    .value(PY_ENUM(BuildToolVersion::TOOLS::SWIFT))
    .value(PY_ENUM(BuildToolVersion::TOOLS::LD));

  cls

    .def_property("platform",
        static_cast<getter_t<BuildVersion::PLATFORMS>>(&BuildVersion::platform),
        static_cast<setter_t<BuildVersion::PLATFORMS>>(&BuildVersion::platform),
        "Target " RST_CLASS_REF(.BuildVersion.PLATFORMS) "")

    .def_property("minos",
        static_cast<getter_t<BuildVersion::version_t>>(&BuildVersion::minos),
        static_cast<setter_t<BuildVersion::version_t>>(&BuildVersion::minos),
        "Minimal OS version on which this binary was built to run")

    .def_property("sdk",
        static_cast<getter_t<BuildVersion::version_t>>(&BuildVersion::sdk),
        static_cast<setter_t<BuildVersion::version_t>>(&BuildVersion::sdk),
        "SDK Version")

    .def_property_readonly("tools",
        static_cast<getter_t<BuildVersion::tools_list_t>>(&BuildVersion::tools),
        "List of " RST_CLASS_REF(BuildToolVersion) " used when while this binary")

    .def("__eq__", &BuildVersion::operator==)
    .def("__ne__", &BuildVersion::operator!=)
    .def("__hash__",
        [] (const BuildVersion& version) {
          return Hash::hash(version);
        })

    .def("__str__",
        [] (const BuildVersion& version)
        {
          std::ostringstream stream;
          stream << version;
          return stream.str();
        });


  LIEF::enum_<BuildVersion::PLATFORMS>(cls, "PLATFORMS")
    .value(PY_ENUM(BuildVersion::PLATFORMS::UNKNOWN))
    .value(PY_ENUM(BuildVersion::PLATFORMS::MACOS))
    .value(PY_ENUM(BuildVersion::PLATFORMS::IOS))
    .value(PY_ENUM(BuildVersion::PLATFORMS::TVOS))
    .value(PY_ENUM(BuildVersion::PLATFORMS::WATCHOS));

}

}
}
