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
#include "LIEF/MachO/EncryptionInfo.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (EncryptionInfo::*)(void) const;

template<class T>
using setter_t = void (EncryptionInfo::*)(T);


template<>
void create<EncryptionInfo>(py::module& m) {

  py::class_<EncryptionInfo, LoadCommand>(m, "EncryptionInfo",
      R"delim(
      Class that represents the LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 commands

      The encryption info is usually present in Mach-O executables that
      target iOS to encrypt some sections of the binary
      )delim")

    .def_property("crypt_offset",
        static_cast<getter_t<uint32_t>>(&EncryptionInfo::crypt_offset),
        static_cast<setter_t<uint32_t>>(&EncryptionInfo::crypt_offset),
        "File offset of encrypted range")

    .def_property("crypt_size",
        static_cast<getter_t<uint32_t>>(&EncryptionInfo::crypt_size),
        static_cast<setter_t<uint32_t>>(&EncryptionInfo::crypt_size),
        "File size of encrypted range")

    .def_property("crypt_id",
        static_cast<getter_t<uint32_t>>(&EncryptionInfo::crypt_id),
        static_cast<setter_t<uint32_t>>(&EncryptionInfo::crypt_id),
        "The encryption system. 0 means no encrypted")



    .def("__eq__", &EncryptionInfo::operator==)
    .def("__ne__", &EncryptionInfo::operator!=)
    .def("__hash__",
        [] (const EncryptionInfo& uuid) {
          return Hash::hash(uuid);
        })


    .def("__str__",
        [] (const EncryptionInfo& uuid)
        {
          std::ostringstream stream;
          stream << uuid;
          std::string str = stream.str();
          return str;
        });
}

}
}
