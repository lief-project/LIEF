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

#include "LIEF/MachO/FilesetCommand.hpp"
#include "LIEF/MachO/Binary.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<FilesetCommand>(nb::module_& m) {
  nb::class_<FilesetCommand, LoadCommand>(m, "FilesetCommand",
     "Class associated with the LC_FILESET_ENTRY commands"_doc)
    .def_prop_rw("name",
        nb::overload_cast<>(&FilesetCommand::name, nb::const_),
        nb::overload_cast<std::string>(&FilesetCommand::name),
        "Name of the underlying MachO binary"_doc)

    .def_prop_rw("virtual_address",
        nb::overload_cast<>(&FilesetCommand::virtual_address, nb::const_),
        nb::overload_cast<uint64_t>(&FilesetCommand::virtual_address),
        "Memory address where the MachO file should be mapped"_doc)

    .def_prop_rw("file_offset",
        nb::overload_cast<>(&FilesetCommand::file_offset, nb::const_),
        nb::overload_cast<uint64_t>(&FilesetCommand::file_offset),
        "Original offset in the kernel cache"_doc)

    .def_prop_ro("binary",
        nb::overload_cast<>(&FilesetCommand::binary, nb::const_),
        "Return the " RST_CLASS_REF(lief.MachO.Binary) " object associated with the entry"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(FilesetCommand);
}
}
