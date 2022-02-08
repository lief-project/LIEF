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
#include "LIEF/MachO/DyldEnvironment.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DyldEnvironment::*)(void) const;

template<class T>
using setter_t = void (DyldEnvironment::*)(T);


template<>
void create<DyldEnvironment>(py::module& m) {

  py::class_<DyldEnvironment, LoadCommand>(m, "DyldEnvironment",
      R"delim(
      Class that represents a LC_DYLD_ENVIRONMENT which is
      used by the Mach-O linker/loader to initialize an environment variable
      )delim")

    .def_property("value",
        static_cast<getter_t<const std::string&>>(&DyldEnvironment::value),
        static_cast<setter_t<const std::string&>>(&DyldEnvironment::value),
        "Environment variable as a string",
        py::return_value_policy::reference_internal)

    .def("__eq__", &DyldEnvironment::operator==)
    .def("__ne__", &DyldEnvironment::operator!=)
    .def("__hash__",
        [] (const DyldEnvironment& env) {
          return Hash::hash(env);
        })


    .def("__str__",
        [] (const DyldEnvironment& env)
        {
          std::ostringstream stream;
          stream << env;
          return stream.str();
        });

}

}
}
