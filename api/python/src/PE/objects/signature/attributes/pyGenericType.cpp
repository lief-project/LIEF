/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/PE/signature/attributes/GenericType.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<GenericType>(nb::module_& m) {
  nb::class_<GenericType, Attribute>(m, "GenericType",
    R"delim(
    Interface over an attribute for which the internal structure is not supported by LIEF
    )delim"_doc)
    .def_prop_ro("oid",
        &GenericType::oid,
        "OID of the original attribute"_doc)

    .def_prop_ro("raw_content",
        [] (const GenericType& type) {
          return nb::to_memoryview(type.raw_content());
        }, "Original DER blob of the attribute"_doc);
}

}
