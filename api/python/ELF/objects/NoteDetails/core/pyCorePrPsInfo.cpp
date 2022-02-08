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

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (CorePrPsInfo::*)(void) const;

template<class T>
using setter_t = void (CorePrPsInfo::*)(T);

template<>
void create<CorePrPsInfo>(py::module& m) {

  py::class_<CorePrPsInfo, NoteDetails>(m, "CorePrPsInfo")

    .def_property("file_name",
        static_cast<getter_t<std::string>>(&CorePrPsInfo::file_name),
        static_cast<setter_t<const std::string&>>(&CorePrPsInfo::file_name),
        "Process file name"
        )

    .def_property("flags",
        static_cast<getter_t<uint64_t>>(&CorePrPsInfo::flags),
        static_cast<setter_t<uint64_t>>(&CorePrPsInfo::flags),
        "Process flags"
        )

    .def_property("uid",
        static_cast<getter_t<uint32_t>>(&CorePrPsInfo::uid),
        static_cast<setter_t<uint32_t>>(&CorePrPsInfo::uid),
        "Process User ID"
        )

    .def_property("gid",
        static_cast<getter_t<uint32_t>>(&CorePrPsInfo::gid),
        static_cast<setter_t<uint32_t>>(&CorePrPsInfo::gid),
        "Process Group ID"
        )

    .def_property("pid",
        static_cast<getter_t<int32_t>>(&CorePrPsInfo::pid),
        static_cast<setter_t<int32_t>>(&CorePrPsInfo::pid),
        "Process ID"
        )

    .def_property("ppid",
        static_cast<getter_t<int32_t>>(&CorePrPsInfo::ppid),
        static_cast<setter_t<int32_t>>(&CorePrPsInfo::ppid),
        "Process parent ID"
        )

    .def_property("pgrp",
        static_cast<getter_t<int32_t>>(&CorePrPsInfo::pgrp),
        static_cast<setter_t<int32_t>>(&CorePrPsInfo::pgrp),
        "Process session group ID"
        )

    .def_property("sid",
        static_cast<getter_t<int32_t>>(&CorePrPsInfo::sid),
        static_cast<setter_t<int32_t>>(&CorePrPsInfo::sid),
        "Process session ID"
        )

    .def("__eq__", &CorePrPsInfo::operator==)
    .def("__ne__", &CorePrPsInfo::operator!=)
    .def("__hash__",
        [] (const CorePrPsInfo& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const CorePrPsInfo& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}

}
}
