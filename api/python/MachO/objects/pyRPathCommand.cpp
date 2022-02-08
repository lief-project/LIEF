/* Copyright 2017 - 2021 J.Rieck (based on R. Thomas's work)
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
#include "LIEF/MachO/RPathCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (RPathCommand::*)(void) const;

template<class T>
using setter_t = void (RPathCommand::*)(T);


template<>
void create<RPathCommand>(py::module& m) {

  py::class_<RPathCommand, LoadCommand>(m, "RPathCommand")

    .def_property("path",
        static_cast<getter_t<const std::string&>>(&RPathCommand::path),
        static_cast<setter_t<const std::string&>>(&RPathCommand::path),
        "@rpath path",
        py::return_value_policy::reference_internal)


    .def("__eq__", &RPathCommand::operator==)
    .def("__ne__", &RPathCommand::operator!=)
    .def("__hash__",
        [] (const RPathCommand& rpath_command) {
          return Hash::hash(rpath_command);
        })


    .def("__str__",
        [] (const RPathCommand& rpath_command)
        {
          std::ostringstream stream;
          stream << rpath_command;
          std::string str = stream.str();
          return str;
        });

}

}
}
