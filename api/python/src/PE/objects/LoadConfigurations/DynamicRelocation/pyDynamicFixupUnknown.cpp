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
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupUnknown.hpp"

#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::PE::py {

template<>
void create<DynamicFixupUnknown>(nb::module_& m) {
  nb::class_<DynamicFixupUnknown, DynamicFixup> obj(m, "DynamicFixupUnknown",
    R"doc(
    This class represents an special dynamic relocation where the format of the
    fixups is not supported by LIEF.
    )doc"_doc
  );
  obj
    .def_prop_ro("payload",
      nb::overload_cast<>(&DynamicFixupUnknown::payload),
      "Raw fixups"_doc);
}

}
