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
#include "LIEF/MachO/ThreadCommand.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (ThreadCommand::*)(void) const;

template<class T>
using setter_t = void (ThreadCommand::*)(T);


void init_MachO_ThreadCommand_class(py::module& m) {

  py::class_<ThreadCommand, LoadCommand>(m, "ThreadCommand")

    .def_property("flavor",
        static_cast<getter_t<uint32_t>>(&ThreadCommand::flavor),
        static_cast<setter_t<uint32_t>>(&ThreadCommand::flavor),
        "",
        py::return_value_policy::reference_internal)


    .def_property("state",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&ThreadCommand::state),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&ThreadCommand::state),
        "",
        py::return_value_policy::reference_internal)


    .def_property("count",
        static_cast<getter_t<uint32_t>>(&ThreadCommand::count),
        static_cast<setter_t<uint32_t>>(&ThreadCommand::count),
        "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("pc",
        static_cast<getter_t<uint64_t>>(&ThreadCommand::pc),
        py::return_value_policy::reference_internal)

    .def("__eq__", &ThreadCommand::operator==)
    .def("__ne__", &ThreadCommand::operator!=)
    .def("__hash__",
        [] (const ThreadCommand& thread) {
          return LIEF::Hash::hash(thread);
        })


    .def("__str__",
        [] (const ThreadCommand& thread)
        {
          std::ostringstream stream;
          stream << thread;
          std::string str = stream.str();
          return str;
        });

}
