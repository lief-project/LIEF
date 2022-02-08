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
#include "LIEF/MachO/UUIDCommand.hpp"

#include "pyMachO.hpp"

#ifdef uuid_t
#pragma message("Windows #define uuid_t, undefine it for this file.")
#undef uuid_t
#endif

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (UUIDCommand::*)(void) const;

template<class T>
using setter_t = void (UUIDCommand::*)(T);


template<>
void create<UUIDCommand>(py::module& m) {

  py::class_<UUIDCommand, LoadCommand>(m, "UUIDCommand",
      "Class that represents the UUID command")

    .def_property("uuid",
        static_cast<getter_t<LIEF::MachO::uuid_t>>(&UUIDCommand::uuid),
        static_cast<setter_t<const LIEF::MachO::uuid_t&>>(&UUIDCommand::uuid),
        "UUID as a list",
        py::return_value_policy::reference_internal)


    .def("__eq__", &UUIDCommand::operator==)
    .def("__ne__", &UUIDCommand::operator!=)
    .def("__hash__",
        [] (const UUIDCommand& uuid) {
          return Hash::hash(uuid);
        })


    .def("__str__",
        [] (const UUIDCommand& uuid)
        {
          std::ostringstream stream;
          stream << uuid;
          std::string str = stream.str();
          return str;
        });
}

}
}
