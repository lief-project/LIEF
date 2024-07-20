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

#include "LIEF/PE/signature/attributes/SigningCertificateV2.hpp"

namespace LIEF::PE::py {

template<>
void create<SigningCertificateV2>(nb::module_& m) {
  nb::class_<SigningCertificateV2, Attribute>(m, "SigningCertificateV2",
    R"doc(
    .. code-block:: text

      SigningCertificateV2 ::= SEQUENCE {
        certs    SEQUENCE OF ESSCertIDv2,
        policies SEQUENCE OF PolicyInformation OPTIONAL
      }

      ESSCertIDv2 ::= SEQUENCE {
        hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
        certHash      OCTET STRING,
        issuerSerial  IssuerSerial OPTIONAL
      }

      IssuerSerial ::= SEQUENCE {
        issuer       GeneralNames,
        serialNumber CertificateSerialNumber
      }

      PolicyInformation ::= SEQUENCE {
        policyIdentifier   OBJECT IDENTIFIER,
        policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
      }
    )doc"_doc
  )
  ;
}

}
