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
void create<LoadConfigurationV11>(nb::module_& m) {
  nb::class_<LoadConfigurationV11, LoadConfigurationV10>(m, "LoadConfigurationV11")
    .def(nb::init<>())

    .def_prop_rw("cast_guard_os_determined_failure_mode",
        nb::overload_cast<>(&LoadConfigurationV11::cast_guard_os_determined_failure_mode, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV11::cast_guard_os_determined_failure_mode),
        ""_doc)

    LIEF_COPYABLE(LoadConfigurationV11)
    LIEF_DEFAULT_STR(LoadConfigurationV11);
}
}
