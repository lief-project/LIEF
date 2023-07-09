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
#include "PE/pyPE.hpp"

#include "LIEF/PE/CodeViewPDB.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

namespace LIEF::PE::py {

template<>
void create<CodeViewPDB>(nb::module_& m) {
  nb::class_<CodeViewPDB, CodeView>(m, "CodeViewPDB")
    .def(nb::init<>())

    .def_prop_rw("signature",
        nb::overload_cast<>(&CodeViewPDB::signature, nb::const_),
        nb::overload_cast<CodeViewPDB::signature_t>(&CodeViewPDB::signature))

    .def_prop_rw("age",
        nb::overload_cast<>(&CodeViewPDB::age, nb::const_),
        nb::overload_cast<uint32_t>(&CodeViewPDB::age))

    .def_prop_rw("filename",
        nb::overload_cast<>(&CodeViewPDB::filename, nb::const_),
        nb::overload_cast<const std::string&>(&CodeViewPDB::filename))

    LIEF_DEFAULT_STR(LIEF::PE::CodeViewPDB);
}

}
