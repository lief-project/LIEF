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
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupControlTransfer.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<DynamicFixupControlTransfer>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<DynamicFixupControlTransfer, DynamicFixup> obj(m, "DynamicFixupControlTransfer",
    R"doc(
    This class wraps fixups associated with the (special) symbol value:
    ``IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER (3)``.
    )doc"_doc
  );

  obj.def_ro_static("NO_IAT_INDEX",&DynamicFixupControlTransfer::NO_IAT_INDEX);

  init_ref_iterator<DynamicFixupControlTransfer::it_relocations>(obj, "it_relocations");

  using reloc_entry_t = DynamicFixupControlTransfer::reloc_entry_t;
  nb::class_<reloc_entry_t>(obj, "reloc_entry_t",
    "Mirror `IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION`"_doc
  )
    .def_rw("rva", &reloc_entry_t::rva,
      "RVA to the instruction"_doc)

    .def_rw("is_call", &reloc_entry_t::is_call,
      "True if target instruction is a ``call``, false otherwise"_doc)

    .def_rw("iat_index", &reloc_entry_t::iat_index,
      R"doc(
      IAT index of the corresponding import. ``0x7FFF`` is a special value
      indicating no index.
      )doc"_doc)
    LIEF_DEFAULT_STR(reloc_entry_t);

  obj
    .def_prop_ro("relocations",
      nb::overload_cast<>(&DynamicFixupControlTransfer::relocations),
      "Iterator over the relocations"_doc,
      nb::keep_alive<0, 1>(), nb::rv_policy::reference_internal
    );
}

}
