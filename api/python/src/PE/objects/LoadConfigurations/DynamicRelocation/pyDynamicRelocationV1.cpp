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
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicRelocationV1.hpp"

namespace LIEF::PE::py {

template<>
void create<DynamicRelocationV1>(nb::module_& m) {
  nb::class_<DynamicRelocationV1, DynamicRelocation> obj(m, "DynamicRelocationV1",
    R"doc(
    This class represents a dynamic relocation (``IMAGE_DYNAMIC_RELOCATION32`` or
    ``IMAGE_DYNAMIC_RELOCATION64``).
    )doc"_doc
  );
}

}
