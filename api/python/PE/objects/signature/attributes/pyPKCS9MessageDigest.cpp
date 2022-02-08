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
#include "LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (PKCS9MessageDigest::*)(void) const;

template<class T>
using setter_t = void (PKCS9MessageDigest::*)(T);


template<>
void create<PKCS9MessageDigest>(py::module& m) {
  py::class_<PKCS9MessageDigest, Attribute>(m, "PKCS9MessageDigest",
    R"delim(
    Interface over the structure described by the OID ``1.2.840.113549.1.9.4`` (PKCS #9)

    The internal structure is described in the
    `RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0 <https://tools.ietf.org/html/rfc2985>`_

    .. code-block:: text

        messageDigest ATTRIBUTE ::= {
          WITH SYNTAX MessageDigest
          EQUALITY MATCHING RULE octet
          SINGLE VALUE TRUE
          ID pkcs-9-at-messageDigest
        }

        MessageDigest ::= OCTET STRING

    )delim")

    .def_property_readonly("digest",
        [] (const PKCS9MessageDigest& digest) -> py::object {
          const std::vector<uint8_t>& data = digest.digest();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Message digeset as a blob of bytes as described in the RFC")

    .def("__hash__",
        [] (const PKCS9MessageDigest& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &PKCS9MessageDigest::print);
}

}
}
