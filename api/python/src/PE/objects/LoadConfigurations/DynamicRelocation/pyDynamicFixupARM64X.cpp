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
#include "enums_wrapper.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupARM64X.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<DynamicFixupARM64X>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<DynamicFixupARM64X, DynamicFixup> obj(m, "DynamicFixupARM64X",
    R"doc(
    This class represents ``IMAGE_DYNAMIC_RELOCATION_ARM64X``
    )doc"_doc
  );
  using FIXUP_TYPE = DynamicFixupARM64X::FIXUP_TYPE;
  enum_<FIXUP_TYPE>(obj, "FIXUP_TYPE")
    .value("ZEROFILL", FIXUP_TYPE::ZEROFILL)
    .value("VALUE", FIXUP_TYPE::VALUE)
    .value("DELTA", FIXUP_TYPE::DELTA);

  using reloc_entry_t = DynamicFixupARM64X::reloc_entry_t;
  nb::class_<reloc_entry_t>(obj, "reloc_entry_t")
    .def_rw("rva", &reloc_entry_t::rva,
            "RVA where the fixup takes place"_doc)
    .def_rw("type", &reloc_entry_t::type,
            "Fixup's kind"_doc)
    .def_rw("size", &reloc_entry_t::size,
            "Size of the value to patch"_doc)
    .def_rw("raw_bytes", &reloc_entry_t::bytes,
      R"doc(
      If the type is class:`~.FIXUP_TYPE.VALUE`, the bytes associated with the
      fixup.
      )doc"_doc)
    .def_rw("value", &reloc_entry_t::value,
      R"doc(
      If the type is class:`~.FIXUP_TYPE.DELTA`, the (signed) value
      )doc"_doc)
    LIEF_DEFAULT_STR(reloc_entry_t);

  init_ref_iterator<DynamicFixupARM64X::it_relocations>(obj, "it_relocations");

  obj
    .def_prop_ro("relocations", nb::overload_cast<>(&DynamicFixupARM64X::relocations),
      "Iterator over the different fixup entries"_doc,
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>()
    )
  ;
}

}
