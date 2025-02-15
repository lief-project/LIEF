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
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicRelocationBase.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixup.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::PE {
class DynamicRelocationV1;
class DynamicRelocationV2;
}

namespace LIEF::PE::py {

template<>
void create<DynamicRelocation>(nb::module_& m) {
  nb::class_<DynamicRelocation> obj(m, "DynamicRelocation",
    R"doc(
    This is the base class for any ``IMAGE_DYNAMIC_RELOCATION32``,
    ``IMAGE_DYNAMIC_RELOCATION32_V2``, ``IMAGE_DYNAMIC_RELOCATION64``,
    ``IMAGE_DYNAMIC_RELOCATION64_V2`` dynamic relocations.
    )doc"_doc
  );
  using IMAGE_DYNAMIC_RELOCATION = DynamicRelocation::IMAGE_DYNAMIC_RELOCATION;
  enum_<IMAGE_DYNAMIC_RELOCATION>(obj, "IMAGE_DYNAMIC_RELOCATION",
    "Special symbol values as defined in ``link.exe - GetDVRTSpecialSymbolName``"_doc
  )
    .value("RELOCATION_GUARD_RF_PROLOGUE", IMAGE_DYNAMIC_RELOCATION::RELOCATION_GUARD_RF_PROLOGUE,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE``")

    .value("RELOCATION_GUARD_RF_EPILOGUE", IMAGE_DYNAMIC_RELOCATION::RELOCATION_GUARD_RF_EPILOGUE,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE``")

    .value("RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER", IMAGE_DYNAMIC_RELOCATION::RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER``")

    .value("RELOCATION_GUARD_INDIR_CONTROL_TRANSFER", IMAGE_DYNAMIC_RELOCATION::RELOCATION_GUARD_INDIR_CONTROL_TRANSFER,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER``")

    .value("RELOCATION_GUARD_SWITCHTABLE_BRANCH", IMAGE_DYNAMIC_RELOCATION::RELOCATION_GUARD_SWITCHTABLE_BRANCH,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH``")

    .value("RELOCATION_ARM64X", IMAGE_DYNAMIC_RELOCATION::RELOCATION_ARM64X,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_ARM64X``")

    .value("RELOCATION_FUNCTION_OVERRIDE", IMAGE_DYNAMIC_RELOCATION::RELOCATION_FUNCTION_OVERRIDE,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE``")

    .value("RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER", IMAGE_DYNAMIC_RELOCATION::RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER,
           "Mirror ``IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER``")
  ;

  obj
    .def_prop_ro("version", &DynamicRelocation::version,
      "Version of the structure"_doc
    )

    .def_prop_rw("symbol",
      nb::overload_cast<>(&DynamicRelocation::symbol, nb::const_),
      nb::overload_cast<uint64_t>(&DynamicRelocation::symbol),
      R"doc(
      Symbol address. Some values have a special meaning
      (c.f. :class:`~.IMAGE_DYNAMIC_RELOCATION`) and define how fixups are encoded.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("fixups",
      nb::overload_cast<>(&DynamicRelocation::fixups, nb::const_),
      R"doc(
      Return fixups information, where the interpretation may depend on the
      symbol's value
      )doc"_doc, nb::rv_policy::reference_internal
    )

  LIEF_DEFAULT_STR(DynamicRelocation)
  LIEF_CLONABLE(DynamicRelocation);

  create<DynamicRelocationV1>(m);
  create<DynamicRelocationV2>(m);
  create<DynamicFixup>(m);
}

}
