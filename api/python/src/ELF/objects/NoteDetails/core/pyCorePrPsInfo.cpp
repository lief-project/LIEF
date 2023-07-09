/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"

namespace LIEF::ELF::py {

template<>
void create<CorePrPsInfo>(nb::module_& m) {

  nb::class_<CorePrPsInfo, NoteDetails>(m, "CorePrPsInfo")

    .def_prop_rw("file_name",
        nb::overload_cast<>(&CorePrPsInfo::file_name, nb::const_),
        nb::overload_cast<const std::string&>(&CorePrPsInfo::file_name),
        "Process file name"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&CorePrPsInfo::flags, nb::const_),
        nb::overload_cast<uint64_t>(&CorePrPsInfo::flags),
        "Process flags"_doc)

    .def_prop_rw("uid",
        nb::overload_cast<>(&CorePrPsInfo::uid, nb::const_),
        nb::overload_cast<uint32_t>(&CorePrPsInfo::uid),
        "Process User ID"_doc)

    .def_prop_rw("gid",
        nb::overload_cast<>(&CorePrPsInfo::gid, nb::const_),
        nb::overload_cast<uint32_t>(&CorePrPsInfo::gid),
        "Process Group ID"_doc)

    .def_prop_rw("pid",
        nb::overload_cast<>(&CorePrPsInfo::pid, nb::const_),
        nb::overload_cast<int32_t>(&CorePrPsInfo::pid),
        "Process ID"_doc)

    .def_prop_rw("ppid",
        nb::overload_cast<>(&CorePrPsInfo::ppid, nb::const_),
        nb::overload_cast<int32_t>(&CorePrPsInfo::ppid),
        "Process parent ID"_doc)

    .def_prop_rw("pgrp",
        nb::overload_cast<>(&CorePrPsInfo::pgrp, nb::const_),
        nb::overload_cast<int32_t>(&CorePrPsInfo::pgrp),
        "Process session group ID"_doc)

    .def_prop_rw("sid",
        nb::overload_cast<>(&CorePrPsInfo::sid, nb::const_),
        nb::overload_cast<int32_t>(&CorePrPsInfo::sid),
        "Process session ID"_doc)

    LIEF_DEFAULT_STR(LIEF::ELF::CorePrPsInfo);
}

}
