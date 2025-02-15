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

#include "PE/pyPE.hpp"
#include "enums_wrapper.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixup.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE {
class DynamicFixupARM64Kernel;
class DynamicFixupARM64X;
class DynamicFixupControlTransfer;
class DynamicFixupGeneric;
class DynamicFixupUnknown;
class FunctionOverride;
}

namespace LIEF::PE::py {

template<>
void create<DynamicFixup>(nb::module_& m) {
  nb::class_<DynamicFixup> obj(m, "DynamicFixup",
    R"doc(
    This is the base class for any fixups located in :class:`~lief.PE.DynamicRelocation`
    )doc"_doc
  );
  using KIND = DynamicFixup::KIND;
  enum_<KIND>(obj, "KIND")
    .value("UNKNOWN", KIND::UNKNOWN,
      R"doc(
      If the :class:`~lief.PE.DynamicRelocation.symbol` is a special value that is not
      supported by LIEF.
      )doc"_doc
    )
    .value("GENERIC", KIND::GENERIC,
      R"doc(
      If :class:`~lief.PE.DynamicRelocation.symbol` is not a special value.
      )doc"_doc
    )
    .value("ARM64X", KIND::ARM64X,
      R"doc(
      If :class:`~lief.PE.DynamicRelocation.symbol` is set to ``IMAGE_DYNAMIC_RELOCATION_ARM64X``.
      )doc"_doc
    )
    .value("FUNCTION_OVERRIDE", KIND::FUNCTION_OVERRIDE,
      R"doc(
      If :class:`~lief.PE.DynamicRelocation.symbol` is set to ``IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE``.
      )doc"_doc
    )
    .value("ARM64_KERNEL_IMPORT_CALL_TRANSFER", KIND::ARM64_KERNEL_IMPORT_CALL_TRANSFER,
      R"doc(
      If :class:`~lief.PE.DynamicRelocation.symbol` is set to ``IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER``.
      )doc"_doc
    )
  ;

  obj
    .def_prop_ro("kind", &DynamicFixup::kind,
      "Encoding of the fixups"_doc
    )

  LIEF_DEFAULT_STR(DynamicFixup)
  LIEF_CLONABLE(DynamicFixup);

  create<DynamicFixupARM64X>(m);
  create<DynamicFixupControlTransfer>(m);
  create<DynamicFixupARM64Kernel>(m);
  create<DynamicFixupGeneric>(m);
  create<DynamicFixupUnknown>(m);
  create<FunctionOverride>(m);
}

}
