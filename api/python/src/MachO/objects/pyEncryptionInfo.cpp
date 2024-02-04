/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <nanobind/stl/string.h>

#include "LIEF/MachO/EncryptionInfo.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<EncryptionInfo>(nb::module_& m) {

  nb::class_<EncryptionInfo, LoadCommand>(m, "EncryptionInfo",
      R"delim(
      Class that represents the LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 commands

      The encryption info is usually present in Mach-O executables that
      target iOS to encrypt some sections of the binary
      )delim"_doc)

    .def_prop_rw("crypt_offset",
        nb::overload_cast<>(&EncryptionInfo::crypt_offset, nb::const_),
        nb::overload_cast<uint32_t>(&EncryptionInfo::crypt_offset),
        "File offset of encrypted range"_doc)

    .def_prop_rw("crypt_size",
        nb::overload_cast<>(&EncryptionInfo::crypt_size, nb::const_),
        nb::overload_cast<uint32_t>(&EncryptionInfo::crypt_size),
        "File size of encrypted range"_doc)

    .def_prop_rw("crypt_id",
        nb::overload_cast<>(&EncryptionInfo::crypt_id, nb::const_),
        nb::overload_cast<uint32_t>(&EncryptionInfo::crypt_id),
        "The encryption system. 0 means no encrypted"_doc)

    LIEF_DEFAULT_STR(EncryptionInfo);

}
}
