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
#include "LIEF/MachO/DylinkerCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DylinkerCommand::*)(void) const;

template<class T>
using setter_t = void (DylinkerCommand::*)(T);


template<>
void create<DylinkerCommand>(py::module& m) {

  py::class_<DylinkerCommand, LoadCommand>(m, "DylinkerCommand",
      R"delim(
      Class that represents the Mach-O linker, also named loader
      Most of the time, :attr:`~lief.MachO.DylinkerCommand.name` returns ``/usr/lib/dyld``
      )delim")

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&DylinkerCommand::name),
        static_cast<setter_t<const std::string&>>(&DylinkerCommand::name),
        "Path to the loader/linker",
        py::return_value_policy::reference_internal)

    .def("__eq__", &DylinkerCommand::operator==)
    .def("__ne__", &DylinkerCommand::operator!=)
    .def("__hash__",
        [] (const DylinkerCommand& dylinker) {
          return Hash::hash(dylinker);
        })


    .def("__str__",
        [] (const DylinkerCommand& dylinker)
        {
          std::ostringstream stream;
          stream << dylinker;
          std::string str = stream.str();
          return str;
        });

}

}
}
