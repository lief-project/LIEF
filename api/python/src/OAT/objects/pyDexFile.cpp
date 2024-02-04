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
#include "LIEF/OAT/DexFile.hpp"
#include "LIEF/DEX/File.hpp"

#include "OAT/pyOAT.hpp"

#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::OAT::py {
template<>
void create<DexFile>(nb::module_& m) {

  nb::class_<DexFile, Object>(m, "DexFile", "OAT DexFile representation"_doc)
    .def(nb::init<>())

    .def_prop_rw("location",
        nb::overload_cast<>(&DexFile::location, nb::const_),
        nb::overload_cast<const std::string&>(&DexFile::location),
        "Original location of the DEX file"_doc)

    .def_prop_rw("checksum",
        nb::overload_cast<>(&DexFile::checksum, nb::const_),
        nb::overload_cast<uint32_t>(&DexFile::checksum),
        "Checksum of the underlying DEX file"_doc)

    .def_prop_rw("dex_offset",
        nb::overload_cast<>(&DexFile::dex_offset, nb::const_),
        nb::overload_cast<uint32_t>(&DexFile::dex_offset),
        "Offset to the raw " RST_CLASS_REF_FULL(lief.DEX.File) ""_doc)

    .def_prop_ro("has_dex_file",
        &DexFile::has_dex_file,
        "Check if the " RST_CLASS_REF_FULL(lief.DEX.File) " is present"_doc)

    .def_prop_ro("dex_file", nb::overload_cast<>(&DexFile::dex_file),
        "Associated " RST_CLASS_REF_FULL(lief.DEX.File) ""_doc)

    LIEF_DEFAULT_STR(DexFile);

}
}

