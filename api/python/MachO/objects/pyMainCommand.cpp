/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/MachO/MainCommand.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (MainCommand::*)(void) const;

template<class T>
using setter_t = void (MainCommand::*)(T);


void init_MachO_MainCommand_class(py::module& m) {

  py::class_<MainCommand, LoadCommand>(m, "MainCommand")

    .def_property("entrypoint",
        static_cast<getter_t<uint64_t>>(&MainCommand::entrypoint),
        static_cast<setter_t<uint64_t>>(&MainCommand::entrypoint),
        "Program entry point",
        py::return_value_policy::reference_internal)

    .def_property("stack_size",
        static_cast<getter_t<uint64_t>>(&MainCommand::stack_size),
        static_cast<setter_t<uint64_t>>(&MainCommand::stack_size),
        "Program stack_size",
        py::return_value_policy::reference_internal)


    .def("__eq__", &MainCommand::operator==)
    .def("__ne__", &MainCommand::operator!=)
    .def("__hash__",
        [] (const MainCommand& main) {
          return Hash::hash(main);
        })


    .def("__str__",
        [] (const MainCommand& main)
        {
          std::ostringstream stream;
          stream << main;
          std::string str = stream.str();
          return str;
        });

}
