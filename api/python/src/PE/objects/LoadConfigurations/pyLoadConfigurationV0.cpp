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
void create<LoadConfigurationV0>(nb::module_& m) {
  nb::class_<LoadConfigurationV0, LoadConfiguration>(m, "LoadConfigurationV0",
    R"delim(
    :class:`~lief.PE.LoadConfiguration` enhanced with SEH.
    It is associated with the :class:`~lief.PE.WIN_VERSION`: :attr:`~lief.PE.WIN_VERSION.SEH`
    )delim"_doc)

    .def(nb::init<>())

    .def_prop_rw("se_handler_table",
        nb::overload_cast<>(&LoadConfigurationV0::se_handler_table, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV0::se_handler_table),
        "The VA of the sorted table of RVAs of each valid, unique "
        "SE handler in the image."_doc)

    .def_prop_rw("se_handler_count",
        nb::overload_cast<>(&LoadConfigurationV0::se_handler_count, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV0::se_handler_count),
        "The count of unique handlers in the table."_doc)

    LIEF_COPYABLE(LoadConfigurationV0)
    LIEF_DEFAULT_STR(LoadConfigurationV0);
}

}
