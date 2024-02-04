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
void create<LoadConfigurationV3>(nb::module_& m) {
  nb::class_<LoadConfigurationV3, LoadConfigurationV2>(m, "LoadConfigurationV3",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV2` with Control Flow Guard improved.

      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN10_0_14286`
      )delim"_doc)

    .def(nb::init<>())

    .def_prop_rw("guard_address_taken_iat_entry_table",
        nb::overload_cast<>(&LoadConfigurationV3::guard_address_taken_iat_entry_table, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV3::guard_address_taken_iat_entry_table),
        "VA of a table associated with CFG's *IAT* checks"_doc)

    .def_prop_rw("guard_address_taken_iat_entry_count",
        nb::overload_cast<>(&LoadConfigurationV3::guard_address_taken_iat_entry_count, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV3::guard_address_taken_iat_entry_count),
        "Number of entries in the :attr:`~lief.PE.guard_address_taken_iat_entry_table`"_doc)

    .def_prop_rw("guard_long_jump_target_table",
        nb::overload_cast<>(&LoadConfigurationV3::guard_long_jump_target_table, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV3::guard_long_jump_target_table),
        "VA of a table associated with CFG's *long jump*"_doc)

    .def_prop_rw("guard_long_jump_target_count",
        nb::overload_cast<>(&LoadConfigurationV3::guard_long_jump_target_count, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV3::guard_long_jump_target_count),
        "Number of entries in the :attr:`~lief.PE.guard_address_taken_iat_entry_table`"_doc)

    LIEF_COPYABLE(LoadConfigurationV3)
    LIEF_DEFAULT_STR(LoadConfigurationV3);

}

}
