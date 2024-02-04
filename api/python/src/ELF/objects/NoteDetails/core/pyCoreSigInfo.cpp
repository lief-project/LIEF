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

#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"

namespace LIEF::ELF::py {

template<>
void create<CoreSigInfo>(nb::module_& m) {

  nb::class_<CoreSigInfo, Note>(m, "CoreSigInfo")
    .def_prop_rw("signo",
        [] (const CoreSigInfo& self) {
          return LIEF::py::value_or_none(nb::overload_cast<>(&CoreSigInfo::signo, nb::const_), self);
        },
        nb::overload_cast<uint32_t>(&CoreSigInfo::signo),
        "Signal number"_doc)

    .def_prop_rw("sigcode",
        [] (const CoreSigInfo& self) {
          return LIEF::py::value_or_none(nb::overload_cast<>(&CoreSigInfo::sigcode, nb::const_), self);
        },
        nb::overload_cast<uint32_t>(&CoreSigInfo::sigcode),
        "Signal code"_doc)

    .def_prop_rw("sigerrno",
        [] (const CoreSigInfo& self) {
          return LIEF::py::value_or_none(nb::overload_cast<>(&CoreSigInfo::sigerrno, nb::const_), self);
        },
        nb::overload_cast<uint32_t>(&CoreSigInfo::sigerrno),
        "If non-zero, an errno value associated with this signal"_doc)

    LIEF_DEFAULT_STR(CoreSigInfo);
}
}
