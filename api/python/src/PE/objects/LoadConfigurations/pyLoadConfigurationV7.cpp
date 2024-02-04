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
void create<LoadConfigurationV7>(nb::module_& m) {
  nb::class_<LoadConfigurationV7, LoadConfigurationV6>(m, "LoadConfigurationV7")
    .def(nb::init<>())

    .def_prop_rw("reserved3",
        nb::overload_cast<>(&LoadConfigurationV7::reserved3, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfigurationV7::reserved3))

    .def_prop_rw("addressof_unicode_string",
        nb::overload_cast<>(&LoadConfigurationV7::addressof_unicode_string, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV7::addressof_unicode_string))

    LIEF_COPYABLE(LoadConfigurationV7)
    LIEF_DEFAULT_STR(LoadConfigurationV7);
}
}
