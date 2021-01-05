/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/PE/signature/attributes/ContentType.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ContentType::*)(void) const;

template<class T>
using setter_t = void (ContentType::*)(T);


template<>
void create<ContentType>(py::module& m) {
  py::class_<ContentType, Attribute>(m, "ContentType")
    .def_property_readonly("oid",
        &ContentType::oid)

    .def("__hash__",
        [] (const ContentType& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &ContentType::print);
}

}
}
