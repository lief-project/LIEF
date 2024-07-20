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

#include "LIEF/PE/signature/PKCS9TSTInfo.hpp"

namespace LIEF::PE::py {

template<>
void create<PKCS9TSTInfo>(nb::module_& m) {
  nb::class_<PKCS9TSTInfo, ContentInfo::Content>(m, "PKCS9TSTInfo",
    R"doc(
    Interface over the structure described by the OID ``1.2.840.113549.1.9.16.1.4`` (PKCS #9)

    The internal structure is described in the `RFC #3161 <https://tools.ietf.org/html/rfc3161>`_

    .. code-block:: text

      TSTInfo ::= SEQUENCE  {
       version        INTEGER  { v1(1) },
       policy         TSAPolicyId,
       messageImprint MessageImprint,
       serialNumber   INTEGER,
       genTime        GeneralizedTime,
       accuracy       Accuracy                OPTIONAL,
       ordering       BOOLEAN                 DEFAULT FALSE,
       nonce          INTEGER                 OPTIONAL,
       tsa            [0] GeneralName         OPTIONAL,
       extensions     [1] IMPLICIT Extensions OPTIONAL
      }

      TSAPolicyId    ::= OBJECT IDENTIFIER
      MessageImprint ::= SEQUENCE {
        hashAlgorithm  AlgorithmIdentifier,
        hashedMessage  OCTET STRING
      }

      Accuracy ::= SEQUENCE {
        seconds        INTEGER           OPTIONAL,
        millis     [0] INTEGER  (1..999) OPTIONAL,
        micros     [1] INTEGER  (1..999) OPTIONAL
      }
    )doc"_doc
  );
}

}

