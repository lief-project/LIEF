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
#include "LIEF/PE/signature/attributes/PKCS9CounterSignature.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (PKCS9CounterSignature::*)(void) const;

template<class T>
using setter_t = void (PKCS9CounterSignature::*)(T);


template<>
void create<PKCS9CounterSignature>(py::module& m) {
  py::class_<PKCS9CounterSignature, Attribute>(m, "PKCS9CounterSignature",
    R"delim(
    Interface over the structure described by the OID ``1.2.840.113549.1.9.6`` (PKCS #9)

    The internal structure is described in the
    `RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0 <https://tools.ietf.org/html/rfc2985>`_

    .. code-block:: text

        counterSignature ATTRIBUTE ::= {
          WITH SYNTAX SignerInfo
          ID pkcs-9-at-counterSignature
        }

    )delim")
    .def_property_readonly("signer",
        &PKCS9CounterSignature::signer,
        "Return the " RST_CLASS_REF(lief.PE.SignerInfo) " as described in the RFC #2985",
        py::return_value_policy::reference)

    .def("__hash__",
        [] (const PKCS9CounterSignature& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &PKCS9CounterSignature::print);
}

}
}
