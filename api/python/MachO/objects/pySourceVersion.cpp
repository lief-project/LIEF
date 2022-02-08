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
#include "LIEF/MachO/SourceVersion.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (SourceVersion::*)(void) const;

template<class T>
using setter_t = void (SourceVersion::*)(T);


template<>
void create<SourceVersion>(py::module& m) {

  py::class_<SourceVersion, LoadCommand>(m, "SourceVersion",
      R"delim(
      Class that represents the MachO LOAD_COMMAND_TYPES::LC_SOURCE_VERSION
      This command is used to provide the *version* of the sources used to build the binary
      )delim")

    .def_property("version",
        static_cast<getter_t<const SourceVersion::version_t&>>(&SourceVersion::version),
        static_cast<setter_t<const SourceVersion::version_t&>>(&SourceVersion::version),
        "Version as a tuple of **5** integers",
        py::return_value_policy::reference_internal)


    .def("__eq__", &SourceVersion::operator==)
    .def("__ne__", &SourceVersion::operator!=)
    .def("__hash__",
        [] (const SourceVersion& version) {
          return Hash::hash(version);
        })


    .def("__str__",
        [] (const SourceVersion& version)
        {
          std::ostringstream stream;
          stream << version;
          std::string str = stream.str();
          return str;
        });
}

}
}
