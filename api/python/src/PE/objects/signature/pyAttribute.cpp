/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "LIEF/PE/signature/Attribute.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<Attribute>(nb::module_& m) {
  nb::class_<Attribute, Object>(m, "Attribute", "Interface over PKCS #7 attribute"_doc)
    .def_prop_ro("type",
        &Attribute::type,
        "Concrete type (" RST_CLASS_REF(lief.PE.SIG_ATTRIBUTE_TYPES) ") of the attribute"_doc)

    LIEF_DEFAULT_STR(Attribute);
}
}
