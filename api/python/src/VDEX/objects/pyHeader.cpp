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
#include "LIEF/VDEX/Header.hpp"

#include "VDEX/pyVDEX.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

namespace LIEF::VDEX::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, Object>(m, "Header", "VDEX Header representation"_doc)

    .def_prop_ro("magic",
        nb::overload_cast<>(&Header::magic, nb::const_),
        "Magic value used to identify VDEX"_doc)

    .def_prop_ro("version",
        nb::overload_cast<>(&Header::version, nb::const_),
        "VDEX version number"_doc)

    .def_prop_ro("nb_dex_files",
        nb::overload_cast<>(&Header::nb_dex_files, nb::const_),
        "Number of " RST_CLASS_REF(lief.DEX.File) " files registered"_doc)

    .def_prop_ro("dex_size",
        nb::overload_cast<>(&Header::dex_size, nb::const_),
        "Size of **all** " RST_CLASS_REF(lief.DEX.File) ""_doc)

    .def_prop_ro("verifier_deps_size",
        nb::overload_cast<>(&Header::verifier_deps_size, nb::const_),
        "Size of verifier deps section"_doc)

    .def_prop_ro("quickening_info_size",
        nb::overload_cast<>(&Header::quickening_info_size, nb::const_),
        "Size of quickening info section"_doc)

    LIEF_DEFAULT_STR(Header);

}

}
