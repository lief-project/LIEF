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

#include "LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<PKCS9MessageDigest>(nb::module_& m) {
  nb::class_<PKCS9MessageDigest, Attribute>(m, "PKCS9MessageDigest",
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

    )delim"_doc)

    .def_prop_ro("digest",
        [] (const PKCS9MessageDigest& digest) {
          return nb::to_bytes(digest.digest());
        }, "Message digeset as a blob of bytes as described in the RFC"_doc);
}

}
