/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/attributes/GenericType.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (GenericType::*)(void) const;

template<class T>
using setter_t = void (GenericType::*)(T);


template<>
void create<GenericType>(py::module& m) {
  py::class_<GenericType, Attribute>(m, "GenericType",
    R"delim(
    Interface over an attribute for which the internal structure is not supported by LIEF
    )delim")
    .def_property_readonly("oid",
        &GenericType::oid,
        "OID of the original attribute")

    .def_property_readonly("raw_content",
        [] (const GenericType& type) -> py::bytes {
          const std::vector<uint8_t>& raw = type.raw_content();
          return py::bytes(reinterpret_cast<const char*>(raw.data()), raw.size());
        },
        "Original DER blob of the attribute")

    .def("__hash__",
        [] (const GenericType& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &GenericType::print);
}

}
}
