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
#include "LIEF/MachO/VersionMin.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (VersionMin::*)(void) const;

template<class T>
using setter_t = void (VersionMin::*)(T);


template<>
void create<VersionMin>(py::module& m) {

  py::class_<VersionMin, LoadCommand>(m, "VersionMin",
      "Class that wraps the LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, ... commands")

    .def_property("version",
        static_cast<getter_t<const VersionMin::version_t&>>(&VersionMin::version),
        static_cast<setter_t<const VersionMin::version_t&>>(&VersionMin::version),
        "Version as a tuple of **3** integers",
        py::return_value_policy::reference_internal)


    .def_property("sdk",
        static_cast<getter_t<const VersionMin::version_t&>>(&VersionMin::sdk),
        static_cast<setter_t<const VersionMin::version_t&>>(&VersionMin::sdk),
        "SDK as a tuple of **3** integers",
        py::return_value_policy::reference_internal)


    .def("__eq__", &VersionMin::operator==)
    .def("__ne__", &VersionMin::operator!=)
    .def("__hash__",
        [] (const VersionMin& version) {
          return Hash::hash(version);
        })


    .def("__str__",
        [] (const VersionMin& version)
        {
          std::ostringstream stream;
          stream << version;
          std::string str = stream.str();
          return str;
        });

}

}
}
