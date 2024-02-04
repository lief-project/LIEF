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
void create<LoadConfigurationV2>(nb::module_& m) {
  nb::class_<LoadConfigurationV2, LoadConfigurationV1>(m, "LoadConfigurationV2",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV1` enhanced with *code integrity*.
      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN10_0_9879`
      )delim"_doc)

    .def(nb::init<>())

    .def_prop_ro("code_integrity",
        nb::overload_cast<>(&LoadConfigurationV2::code_integrity),
        "" RST_CLASS_REF(lief.PE.CodeIntegrity) " object"_doc,
        nb::rv_policy::reference_internal)

    LIEF_COPYABLE(LoadConfigurationV2)
    LIEF_DEFAULT_STR(LoadConfigurationV2);
}

}
