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
#include "LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (PKCS9SigningTime::*)(void) const;

template<class T>
using setter_t = void (PKCS9SigningTime::*)(T);


template<>
void create<PKCS9SigningTime>(py::module& m) {
  py::class_<PKCS9SigningTime, Attribute>(m, "PKCS9SigningTime",
    R"delim(
    Interface over the structure described by the OID ``1.2.840.113549.1.9.5`` (PKCS #9)

    The internal structure is described in the
    `RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0 <https://tools.ietf.org/html/rfc2985>`_

    .. code-block:: text

        signingTime ATTRIBUTE ::= {
                WITH SYNTAX SigningTime
                EQUALITY MATCHING RULE signingTimeMatch
                SINGLE VALUE TRUE
                ID pkcs-9-at-signingTime
        }

        SigningTime ::= Time -- imported from ISO/IEC 9594-8

    )delim")

    .def_property_readonly("time",
        &PKCS9SigningTime::time,
        "Time as a list [year, month, day, hour, min, sec]")

    .def("__hash__",
        [] (const PKCS9SigningTime& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &PKCS9SigningTime::print);
}

}
}
