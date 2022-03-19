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
#include <sstream>
#include <string>

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"
#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template <class T>
using getter_t = T (PKCS9AtSequenceNumber::*)(void) const;

template <class T>
using setter_t = void (PKCS9AtSequenceNumber::*)(T);

template <>
void create<PKCS9AtSequenceNumber>(py::module& m) {
  py::class_<PKCS9AtSequenceNumber, Attribute>(m, "PKCS9AtSequenceNumber",
                                               R"delim(
    Interface over the structure described by the OID ``1.2.840.113549.1.9.25.4`` (PKCS #9)

    The internal structure is described in the
    `RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0 <https://tools.ietf.org/html/rfc2985>`_

    .. code-block:: text

        sequenceNumber ATTRIBUTE ::= {
          WITH SYNTAX SequenceNumber
          EQUALITY MATCHING RULE integerMat
          SINGLE VALUE TRUE
          ID pkcs-9-at-sequenceNumber
        }

        SequenceNumber ::= INTEGER (1..MAX)

    )delim")

      .def_property_readonly("number", &PKCS9AtSequenceNumber::number,
                             "Number as described in the RFC")

      .def("__hash__",
           [](const PKCS9AtSequenceNumber& obj) { return Hash::hash(obj); })

      .def("__str__", &PKCS9AtSequenceNumber::print);
}

}  // namespace PE
}  // namespace LIEF
