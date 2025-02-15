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
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupGeneric.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<DynamicFixupGeneric>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<DynamicFixupGeneric, DynamicFixup> obj(m, "DynamicFixupGeneric",
    R"doc(
    This class represents a generic entry where the fixups are regular
    relocations (:class:`lief.PE.Relocation`)
    )doc"_doc
  );
  init_ref_iterator<DynamicFixupGeneric::it_relocations>(obj, "it_relocations");

  obj
    .def_prop_ro("relocations", nb::overload_cast<>(&DynamicFixupGeneric::relocations),
      "Iterator over the relocations"_doc,
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>()
    )
  ;
}

}
