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

#include "pyErr.hpp"
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"

namespace LIEF::ELF::py {

template<>
void create<CorePrPsInfo>(nb::module_& m) {
  nb::class_<CorePrPsInfo, Note> cls(m, "CorePrPsInfo");
  nb::class_<CorePrPsInfo::info_t>(cls, "info_t")
    .def_rw("state", &CorePrPsInfo::info_t::state)
    .def_rw("sname", &CorePrPsInfo::info_t::sname)
    .def_rw("zombie", &CorePrPsInfo::info_t::zombie)
    .def_rw("nice", &CorePrPsInfo::info_t::nice)
    .def_rw("flag", &CorePrPsInfo::info_t::flag)
    .def_rw("uid", &CorePrPsInfo::info_t::uid)
    .def_rw("gid", &CorePrPsInfo::info_t::gid)
    .def_rw("pid", &CorePrPsInfo::info_t::pid)
    .def_rw("ppid", &CorePrPsInfo::info_t::ppid)
    .def_rw("pgrp", &CorePrPsInfo::info_t::pgrp)
    .def_rw("sid", &CorePrPsInfo::info_t::sid)
    .def_rw("filename", &CorePrPsInfo::info_t::filename)
    .def_rw("args", &CorePrPsInfo::info_t::args)
    .def_prop_ro("filename_stripped", &CorePrPsInfo::info_t::filename_stripped)
    .def_prop_ro("args_stripped", &CorePrPsInfo::info_t::args_stripped);

  cls
    .def_prop_rw("info",
        [] (const CorePrPsInfo& self) {
          return LIEF::py::value_or_none(nb::overload_cast<>(&CorePrPsInfo::info, nb::const_), self);
        },
        nb::overload_cast<const CorePrPsInfo::info_t&>(&CorePrPsInfo::info)
    )
    LIEF_DEFAULT_STR(CorePrPsInfo);
}

}
