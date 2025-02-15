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
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupARM64Kernel.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<DynamicFixupARM64Kernel>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<DynamicFixupARM64Kernel, DynamicFixup> obj(m, "DynamicFixupARM64Kernel",
    R"doc(
    This class wraps fixups associated with the (special) symbol value:
    ``IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER (8)``.
    )doc"_doc
  );

  obj.def_ro_static("NO_IAT_INDEX",&DynamicFixupARM64Kernel::NO_IAT_INDEX);

  using IMPORT_TYPE = DynamicFixupARM64Kernel::IMPORT_TYPE;
  nb::enum_<IMPORT_TYPE>(obj, "IMPORT_TYPE")
    .value("STATIC", IMPORT_TYPE::STATIC)
    .value("DELAYED", IMPORT_TYPE::DELAYED);

  init_ref_iterator<DynamicFixupARM64Kernel::it_relocations>(obj, "it_relocations");

  using reloc_entry_t = DynamicFixupARM64Kernel::reloc_entry_t;
  nb::class_<reloc_entry_t>(obj, "reloc_entry_t",
    "Mirror ``IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION``"_doc
  )
    .def_rw("rva", &reloc_entry_t::rva,
      "RVA to the call instruction"_doc)

    .def_rw("indirect_call", &reloc_entry_t::indirect_call,
      "True if target instruction is a ``blr``, false if it's a ``br``."_doc)

    .def_rw("register_index", &reloc_entry_t::register_index,
      R"doc(
      Register index used for the indirect call/jump.
      For instance, if the instruction is ``br x3``, this index is set to ``3``
      )doc"_doc)

    .def_rw("import_type", &reloc_entry_t::import_type,
      "See: :class:`~.IMPORT_TYPE`"_doc)

    .def_rw("iat_index", &reloc_entry_t::iat_index,
      R"doc(
      IAT index of the corresponding import. ``0x7FFF`` is a special value
      indicating no index.
      )doc"_doc)
    LIEF_DEFAULT_STR(reloc_entry_t);

  obj
    .def_prop_ro("relocations",
      nb::overload_cast<>(&DynamicFixupARM64Kernel::relocations),
      "Iterator over the relocations"_doc,
      nb::keep_alive<0, 1>(), nb::rv_policy::reference_internal
    );
}

}
