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
void create<LoadConfigurationV4>(nb::module_& m) {
  nb::class_<LoadConfigurationV4, LoadConfigurationV3>(m, "LoadConfigurationV4",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV3` enhanced with:

        * Kind of dynamic relocations
        * *Hybrid Metadata Pointer*

      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN10_0_14383`
      )delim"_doc)
    .def(nb::init<>())

    .def_prop_rw("dynamic_value_reloc_table",
        nb::overload_cast<>(&LoadConfigurationV4::dynamic_value_reloc_table, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV4::dynamic_value_reloc_table),
        "VA of pointing to a ``IMAGE_DYNAMIC_RELOCATION_TABLE``"_doc)

    .def_prop_rw("hybrid_metadata_pointer",
        nb::overload_cast<>(&LoadConfigurationV4::hybrid_metadata_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV4::hybrid_metadata_pointer))

    LIEF_COPYABLE(LoadConfigurationV4)
    LIEF_DEFAULT_STR(LoadConfigurationV4);
}
}
