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
#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/LoadCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (LoadCommand::*)(void) const;

template<class T>
using setter_t = void (LoadCommand::*)(T);


template<>
void create<LoadCommand>(py::module& m) {

  py::class_<LoadCommand, LIEF::Object>(m, "LoadCommand",
      "Based class for the Mach-O load commands")
    .def(py::init<>())

    .def_property("command",
        static_cast<getter_t<LOAD_COMMAND_TYPES>>(&LoadCommand::command),
        static_cast<setter_t<LOAD_COMMAND_TYPES>>(&LoadCommand::command),
        "Command type ( " RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES) ")"
        )

    .def_property("size",
        static_cast<getter_t<uint32_t>>(&LoadCommand::size),
        static_cast<setter_t<uint32_t>>(&LoadCommand::size),
        "Size of the command (should be greather than ``sizeof(load_command)``)")

    .def_property("data",
        static_cast<getter_t<const LoadCommand::raw_t&>>(&LoadCommand::data),
        static_cast<setter_t<const LoadCommand::raw_t&>>(&LoadCommand::data),
        "Command's data")

    .def_property("command_offset",
        static_cast<getter_t<uint64_t>>(&LoadCommand::command_offset),
        static_cast<setter_t<uint64_t>>(&LoadCommand::command_offset),
        "Offset of the command within the *Load Command Table*")

    .def("__eq__", &LoadCommand::operator==)
    .def("__ne__", &LoadCommand::operator!=)
    .def("__hash__",
        [] (const LoadCommand& load_command) {
          return Hash::hash(load_command);
        })

    .def("__str__",
        [] (const LoadCommand& command)
        {
          std::ostringstream stream;
          stream << command;
          std::string str = stream.str();
          return str;
        });
}


}
}
