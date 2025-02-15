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
#include <sstream>
#include "pyIterator.hpp"

#include "PE/pyPE.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/FunctionOverrideInfo.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<FunctionOverrideInfo>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<FunctionOverrideInfo> obj(m, "FunctionOverrideInfo");

  init_ref_iterator<FunctionOverrideInfo::it_relocations>(obj, "it_relocations");

  obj
    .def_prop_rw("original_rva",
      nb::overload_cast<>(&FunctionOverrideInfo::original_rva, nb::const_),
      nb::overload_cast<uint32_t>(&FunctionOverrideInfo::original_rva),
      "RVA of original function"_doc, nb::rv_policy::reference_internal)

    .def_prop_rw("bdd_offset",
      nb::overload_cast<>(&FunctionOverrideInfo::bdd_offset, nb::const_),
      nb::overload_cast<uint32_t>(&FunctionOverrideInfo::bdd_offset),
      "Offset into the BDD region"_doc, nb::rv_policy::reference_internal)

    .def_prop_ro("rva_size",
      nb::overload_cast<>(&FunctionOverrideInfo::rva_size, nb::const_),
      "Size in bytes taken by RVAs"_doc, nb::rv_policy::reference_internal)

    .def_prop_ro("base_reloc_size",
      nb::overload_cast<>(&FunctionOverrideInfo::base_reloc_size, nb::const_),
      "Size in bytes taken by BaseRelocs"_doc, nb::rv_policy::reference_internal)

    .def_prop_ro("relocations",
      nb::overload_cast<>(&FunctionOverrideInfo::relocations),
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>()
    )

    .def_prop_ro("functions_rva",
      nb::overload_cast<>(&FunctionOverrideInfo::functions_rva, nb::const_)
    )

  LIEF_DEFAULT_STR(FunctionOverrideInfo);
}

}
