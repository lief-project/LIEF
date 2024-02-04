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
void create<LoadConfigurationV6>(nb::module_& m) {
  nb::class_<LoadConfigurationV6, LoadConfigurationV5>(m, "LoadConfigurationV6",
    R"delim(
    :class:`~lief.PE.LoadConfigurationV5` enhanced with Hotpatch and improved RFG.

    It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN10_0_15002`
    )delim"_doc)

    .def(nb::init<>())

    .def_prop_rw("guard_rf_verify_stackpointer_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV6::guard_rf_verify_stackpointer_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV6::guard_rf_verify_stackpointer_function_pointer),
        "VA of the Function verifying the stack pointer"_doc)

    .def_prop_rw("hotpatch_table_offset",
        nb::overload_cast<>(&LoadConfigurationV6::hotpatch_table_offset, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfigurationV6::hotpatch_table_offset),
        "Offset to the *hotpatch* table"_doc)

    LIEF_COPYABLE(LoadConfigurationV6)
    LIEF_DEFAULT_STR(LoadConfigurationV6);
}

}
