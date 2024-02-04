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
void create<LoadConfigurationV5>(nb::module_& m) {
  nb::class_<LoadConfigurationV5, LoadConfigurationV4>(m, "LoadConfigurationV5",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV4` enhanced nhanced with Return Flow Guard.

      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN10_0_14901`
      )delim"_doc)

    .def(nb::init<>())

    .def_prop_rw("guard_rf_failure_routine",
        nb::overload_cast<>(&LoadConfigurationV5::guard_rf_failure_routine, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV5::guard_rf_failure_routine),
        "VA of the failure routine"_doc)

    .def_prop_rw("guard_rf_failure_routine_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV5::guard_rf_failure_routine_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV5::guard_rf_failure_routine_function_pointer),
        "VA of the failure routine ``fptr``"_doc)

    .def_prop_rw("dynamic_value_reloctable_offset",
        nb::overload_cast<>(&LoadConfigurationV5::dynamic_value_reloctable_offset, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfigurationV5::dynamic_value_reloctable_offset),
        "Offset of dynamic relocation table relative to the relocation table"_doc)

    .def_prop_rw("dynamic_value_reloctable_section",
        nb::overload_cast<>(&LoadConfigurationV5::dynamic_value_reloctable_section, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfigurationV5::dynamic_value_reloctable_section),
        "The section index of the dynamic value relocation table"_doc)

    .def_prop_rw("reserved2",
        nb::overload_cast<>(&LoadConfigurationV5::reserved2, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfigurationV5::reserved2),
        "Must be zero"_doc)

    LIEF_COPYABLE(LoadConfigurationV5)
    LIEF_DEFAULT_STR(LoadConfigurationV5);
}

}
