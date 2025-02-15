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
#include "pyIterator.hpp"

#include "PE/pyPE.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/FunctionOverride.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/FunctionOverrideInfo.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<FunctionOverride>(nb::module_& m) {
  using namespace LIEF::py;
  create<FunctionOverrideInfo>(m);

  nb::class_<FunctionOverride, DynamicFixup> obj(m, "FunctionOverride",
    "This class represents ``IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE``"_doc
  );

  using image_bdd_dynamic_relocation_t = FunctionOverride::image_bdd_dynamic_relocation_t;
  nb::class_<image_bdd_dynamic_relocation_t>(obj, "image_bdd_dynamic_relocation_t",
    "Mirror ``IMAGE_BDD_DYNAMIC_RELOCATION``"_doc
  )
    .def_rw("left", &image_bdd_dynamic_relocation_t::left)
    .def_rw("right", &image_bdd_dynamic_relocation_t::right)
    .def_rw("value", &image_bdd_dynamic_relocation_t::value);

  using image_bdd_info_t = FunctionOverride::image_bdd_info_t;
  nb::class_<image_bdd_info_t>(obj, "image_bdd_info_t",
    "Mirror ``IMAGE_BDD_INFO``"
  )
    .def_rw("version", &image_bdd_info_t::version)
    .def_rw("original_size", &image_bdd_info_t::original_size)
    .def_rw("original_offset", &image_bdd_info_t::original_offset)
    .def_rw("relocations", &image_bdd_info_t::relocations)
    .def_rw("payload", &image_bdd_info_t::payload);

  init_ref_iterator<FunctionOverride::it_func_overriding_info>(obj, "it_func_overriding_info");
  init_ref_iterator<FunctionOverride::it_bdd_info>(obj, "it_bdd_info");

  obj
    .def_prop_ro("func_overriding_info",
      nb::overload_cast<>(&FunctionOverride::func_overriding_info),
      "Iterator over the overriding info"_doc,
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>()
    )
    .def_prop_ro("bdd_info", nb::overload_cast<>(&FunctionOverride::bdd_info),
      "Iterator over the BDD info"_doc,
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>()
    )

    .def("find_bdd_info",
      nb::overload_cast<uint32_t>(&FunctionOverride::find_bdd_info),
      "Find the ``IMAGE_BDD_INFO`` at the given offset"_doc,
      nb::rv_policy::reference_internal
    )

    .def("find_bdd_info",
      nb::overload_cast<const FunctionOverrideInfo&>(&FunctionOverride::find_bdd_info),
      "Find the ``IMAGE_BDD_INFO`` associated with the given function override info"_doc,
      nb::rv_policy::reference_internal
    )
  ;
}

}
