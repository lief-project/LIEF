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

#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"

namespace LIEF::ELF::py {

template<>
void create<CoreSigInfo>(nb::module_& m) {

  nb::class_<CoreSigInfo, NoteDetails>(m, "CoreSigInfo")

    .def_prop_rw("signo",
        nb::overload_cast<>(&CoreSigInfo::signo, nb::const_),
        nb::overload_cast<int32_t>(&CoreSigInfo::signo),
        "Signal number"_doc)

    .def_prop_rw("sigcode",
        nb::overload_cast<>(&CoreSigInfo::sigcode, nb::const_),
        nb::overload_cast<int32_t>(&CoreSigInfo::sigcode),
        "Signal code"_doc)

    .def_prop_rw("sigerrno",
        nb::overload_cast<>(&CoreSigInfo::sigerrno, nb::const_),
        nb::overload_cast<int32_t>(&CoreSigInfo::sigerrno),
        "If non-zero, an errno value associated with this signal"_doc)

    LIEF_DEFAULT_STR(LIEF::ELF::CoreSigInfo);
}
}
