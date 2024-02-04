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

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/AndroidIdent.hpp"

namespace LIEF::ELF::py {

template<>
void create<AndroidIdent>(nb::module_& m) {
  nb::class_<AndroidIdent, Note>(m, "AndroidIdent")
    .def_prop_rw("sdk_version",
        nb::overload_cast<>(&AndroidIdent::sdk_version, nb::const_),
        nb::overload_cast<uint32_t>(&AndroidIdent::sdk_version),
        "Target SDK platform"_doc)

    .def_prop_rw("ndk_version",
        nb::overload_cast<>(&AndroidIdent::ndk_version, nb::const_),
        nb::overload_cast<const std::string&>(&AndroidIdent::ndk_version),
        "Android NDK version used to build the current binary"_doc)

    .def_prop_rw("ndk_build_number",
        nb::overload_cast<>(&AndroidIdent::ndk_build_number, nb::const_),
        nb::overload_cast<const std::string&>(&AndroidIdent::ndk_build_number),
        "Android NDK build number"_doc)

    LIEF_DEFAULT_STR(AndroidIdent);
}

}
