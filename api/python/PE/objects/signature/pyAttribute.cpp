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

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Attribute::*)(void) const;

template<class T>
using setter_t = void (Attribute::*)(T);


template<>
void create<Attribute>(py::module& m) {
  py::class_<Attribute, Object>(m, "Attribute", "Interface over PKCS #7 attribute")
    .def_property_readonly("type",
        &Attribute::type,
        "Concrete type (" RST_CLASS_REF(lief.PE.SIG_ATTRIBUTE_TYPES) ") of the attribute")

    .def("__str__", [] (const Attribute& attr)
        {
          return attr.print();
        });
}

}
}
