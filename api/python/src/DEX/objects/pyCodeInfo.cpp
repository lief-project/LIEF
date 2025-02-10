/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/DEX/CodeInfo.hpp"

#include "DEX/pyDEX.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>

namespace LIEF::DEX::py {

template<>
void create<CodeInfo>(nb::module_& m) {

  nb::class_<CodeInfo, LIEF::Object>(m, "CodeInfo", "DEX CodeInfo representation"_doc)
    .def_prop_ro("nb_registers", nb::overload_cast<>(&CodeInfo::nb_registers, nb::const_),
    "Number of registers used by the method"_doc)

    LIEF_DEFAULT_STR(CodeInfo);
}
}
