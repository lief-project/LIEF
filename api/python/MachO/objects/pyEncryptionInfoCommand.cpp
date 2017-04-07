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

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/MachO/EncryptionInfoCommand.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (EncryptionInfoCommand::*)(void) const;

template<class T>
using setter_t = void (EncryptionInfoCommand::*)(T);


void init_MachO_EncryptionInfoCommand_class(py::module& m) {

  py::class_<EncryptionInfoCommand, LoadCommand>(m, "EncryptionInfoCommand")
    .def_property("cryptoff",
        static_cast<getter_t<uint32_t>>(&EncryptionInfoCommand::crypt_offset),
        static_cast<setter_t<uint32_t>>(&EncryptionInfoCommand::crypt_offset),
        "Crypto chunk offset",
        py::return_value_policy::reference_internal)

    .def_property("cryptsize",
        static_cast<getter_t<uint32_t>>(&EncryptionInfoCommand::crypt_size),
        static_cast<setter_t<uint32_t>>(&EncryptionInfoCommand::crypt_size),
        "Crypto chunk size",
        py::return_value_policy::reference_internal)
    .def_property("cryptid",
        static_cast<getter_t<uint32_t>>(&EncryptionInfoCommand::crypt_id),
        static_cast<setter_t<uint32_t>>(&EncryptionInfoCommand::crypt_id),
        "Crypto ID",
        py::return_value_policy::reference_internal)
    .def("__eq__", &EncryptionInfoCommand::operator==)
    .def("__ne__", &EncryptionInfoCommand::operator!=)
    .def("__hash__",
        [] (const EncryptionInfoCommand& dylib_command) {
          return LIEF::Hash::hash(dylib_command);
        })


    .def("__str__",
        [] (const EncryptionInfoCommand& command)
        {
          std::ostringstream stream;
          stream << command;
          std::string str = stream.str();
          return str;
        });

}
