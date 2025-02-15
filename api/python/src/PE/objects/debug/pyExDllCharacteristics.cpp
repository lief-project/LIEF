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
#include "PE/pyPE.hpp"
#include "LIEF/PE/debug/ExDllCharacteristics.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/memoryview.hpp>
#include "nanobind/utils.hpp"
#include "enums_wrapper.hpp"

namespace LIEF::PE::py {

template<>
void create<ExDllCharacteristics>(nb::module_& m) {
  nb::class_<ExDllCharacteristics, Debug> dbg(m, "ExDllCharacteristics",
    R"delim(
    This class represents the ``IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS`` debug
    entry
    )delim"_doc);

  using CHARACTERISTICS = ExDllCharacteristics::CHARACTERISTICS;
  enum_<CHARACTERISTICS>(dbg, "CHARACTERISTICS", nb::is_flag(),
    "Extended DLL Characteristics"_doc
  )
    .value("CET_COMPAT", CHARACTERISTICS::CET_COMPAT)
    .value("CET_COMPAT_STRICT_MODE", CHARACTERISTICS::CET_COMPAT_STRICT_MODE)
    .value("CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE", CHARACTERISTICS::CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE)
    .value("CET_DYNAMIC_APIS_ALLOW_IN_PROC", CHARACTERISTICS::CET_DYNAMIC_APIS_ALLOW_IN_PROC)
    .value("CET_RESERVED_1", CHARACTERISTICS::CET_RESERVED_1)
    .value("CET_RESERVED_2", CHARACTERISTICS::CET_RESERVED_2)
    .value("FORWARD_CFI_COMPAT", CHARACTERISTICS::FORWARD_CFI_COMPAT)
    .value("HOTPATCH_COMPATIBLE", CHARACTERISTICS::HOTPATCH_COMPATIBLE);

  dbg
    .def("has", &ExDllCharacteristics::has,
      "Check if the given CHARACTERISTICS is used"_doc, "characteristic"_a
    )
    .def_prop_ro("ex_characteristics", &ExDllCharacteristics::characteristics,
      "The extended characteristics"_doc
    )
    .def_prop_ro("ex_characteristics_list", &ExDllCharacteristics::characteristics_list,
      "Characteristics as a vector"_doc
    );
}
}
