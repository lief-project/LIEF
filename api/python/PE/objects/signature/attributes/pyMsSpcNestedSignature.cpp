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
#include "LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (MsSpcNestedSignature::*)(void) const;

template<class T>
using setter_t = void (MsSpcNestedSignature::*)(T);


template<>
void create<MsSpcNestedSignature>(py::module& m) {
  py::class_<MsSpcNestedSignature, Attribute>(m, "MsSpcNestedSignature")
    .def_property_readonly("signature",
        &MsSpcNestedSignature::sig,
        py::return_value_policy::reference)

    .def("__hash__",
        [] (const MsSpcNestedSignature& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &MsSpcNestedSignature::print);
}

}
}
