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
#include "PE/pyPE.hpp"

#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<LoadConfigurationV10>(nb::module_& m) {
  nb::class_<LoadConfigurationV10, LoadConfigurationV9>(m, "LoadConfigurationV10")
    .def(nb::init<>())

    .def_prop_rw("guard_xfg_check_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV10::guard_xfg_check_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV10::guard_xfg_check_function_pointer),
        ""_doc)

    .def_prop_rw("guard_xfg_dispatch_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV10::guard_xfg_dispatch_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV10::guard_xfg_dispatch_function_pointer),
        ""_doc)

    .def_prop_rw("guard_xfg_table_dispatch_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV10::guard_xfg_table_dispatch_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV10::guard_xfg_table_dispatch_function_pointer),
        ""_doc)

    LIEF_COPYABLE(LoadConfigurationV10)
    LIEF_DEFAULT_STR(LoadConfigurationV10);
}
}
