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

#include "LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<MsSpcNestedSignature>(nb::module_& m) {
  nb::class_<MsSpcNestedSignature, Attribute>(m, "MsSpcNestedSignature",
    R"delim(
    Interface over the structure described by the OID ``1.3.6.1.4.1.311.2.4.1``

    The internal structure is not documented but we can infer the following structure:

    .. code-block:: text

        MsSpcNestedSignature ::= SET OF SignedData

    With ``SignedData``, the structure described in PKCS #7 RFC (See: :class:`lief.PE.Signature`)
    )delim"_doc)
    .def_prop_ro("signature", &MsSpcNestedSignature::sig,
        "Underlying " RST_CLASS_REF(lief.PE.Signature) " object"_doc,
        nb::rv_policy::reference_internal);
}

}
