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
#include "LIEF/MachO/SubFramework.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (SubFramework::*)(void) const;

template<class T>
using setter_t = void (SubFramework::*)(T);


template<>
void create<SubFramework>(py::module& m) {

  py::class_<SubFramework, LoadCommand>(m, "SubFramework",
      R"delim(
      Class that represents the SubFramework command.
      Accodring to the Mach-O ``loader.h`` documentation:


      > A dynamically linked shared library may be a subframework of an umbrella
      > framework.  If so it will be linked with "-umbrella umbrella_name" where
      > Where "umbrella_name" is the name of the umbrella framework. A subframework
      > can only be linked against by its umbrella framework or other subframeworks
      > that are part of the same umbrella framework.  Otherwise the static link
      > editor produces an error and states to link against the umbrella framework.
      > The name of the umbrella framework for subframeworks is recorded in the
      > following structure.
      )delim")

    .def_property("umbrella",
        static_cast<getter_t<const std::string&>>(&SubFramework::umbrella),
        static_cast<setter_t<const std::string&>>(&SubFramework::umbrella),
        "Name of the umbrella framework")

    .def("__eq__", &SubFramework::operator==)
    .def("__ne__", &SubFramework::operator!=)
    .def("__hash__",
        [] (const SubFramework& func) {
          return Hash::hash(func);
        })


    .def("__str__",
        [] (const SubFramework& func)
        {
          std::ostringstream stream;
          stream << func;
          std::string str = stream.str();
          return str;
        });

}

}
}
