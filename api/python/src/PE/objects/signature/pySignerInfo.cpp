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
#include "LIEF/PE/signature/SignerInfo.hpp"
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/x509.hpp"

#include "PE/pyPE.hpp"
#include "pyIterator.hpp"
#include "pySafeString.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<SignerInfo>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<SignerInfo, LIEF::Object> signer(m, "SignerInfo",
    R"delim(
    SignerInfo as described in the `RFC 2315 #Section 9.2 <https://tools.ietf.org/html/rfc2315#section-9.2>`_

    .. code-block:: text

      SignerInfo ::= SEQUENCE {
       version                   Version,
       issuerAndSerialNumber     IssuerAndSerialNumber,
       digestAlgorithm           DigestAlgorithmIdentifier,
       authenticatedAttributes   [0] IMPLICIT Attributes OPTIONAL,
       digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
       encryptedDigest           EncryptedDigest,
       unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
      }

      EncryptedDigest ::= OCTET STRING
    )delim"_doc);

  init_ref_iterator<SignerInfo::it_const_attributes_t>(signer, "it_const_attributes_t");

  signer
    .def_prop_ro("version",
        &SignerInfo::version,
        "Should be 1"_doc)

    .def_prop_ro("serial_number",
        [] (const SignerInfo& info) {
          return nb::to_bytes(info.serial_number());
        },
        "The X509 serial number used to sign the signed-data (see: :attr:`lief.PE.x509.serial_number`)"_doc)

    .def_prop_ro("issuer",
        [] (const SignerInfo& object) {
          return safe_string(object.issuer());
        },
        "The X509 issuer used to sign the signed-data (see: :attr:`lief.PE.x509.issuer`)"_doc,
        nb::rv_policy::copy)

    .def_prop_ro("digest_algorithm",
        &SignerInfo::digest_algorithm,
        "Algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") used to hash the file. "
        "This value should match " RST_ATTR_REF_FULL(ContentInfo.digest_algorithm) " "
        "and " RST_ATTR_REF_FULL(Signature.digest_algorithm) ""_doc)

    .def_prop_ro("encryption_algorithm",
        &SignerInfo::encryption_algorithm,
        "Return algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") used to encrypt the digest"_doc)

    .def_prop_ro("encrypted_digest",
        [] (const SignerInfo& info) {
          return nb::to_bytes(info.encrypted_digest());
        },
        "Return the signature created by the signing certificate's private key"_doc)

    .def_prop_ro("authenticated_attributes",
        &SignerInfo::authenticated_attributes,
        "Return an iterator over the authenticated attributes ("
        "" RST_CLASS_REF(lief.PE.Attribute) ")"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("unauthenticated_attributes",
        &SignerInfo::unauthenticated_attributes,
        "Return an iterator over the unauthenticated attributes ("
        "" RST_CLASS_REF(lief.PE.Attribute) ")"_doc,
        nb::keep_alive<0, 1>())

    .def("get_attribute",
        &SignerInfo::get_attribute,
        R"delim(
        Return the authenticated or un-authenticated attribute matching the
        given :class:`lief.PE.SIG_ATTRIBUTE_TYPES`
        It returns **the first** entry that matches the given type. If it can't be
        found, it returns None
        )delim"_doc,
        "type"_a, nb::rv_policy::reference_internal)

    .def("get_auth_attribute",
        &SignerInfo::get_auth_attribute,
        R"delim(
        Return the authenticated attribute matching the
        given :class:`lief.PE.SIG_ATTRIBUTE_TYPES`
        It returns **the first** entry that matches the given type. If it can't be
        found, it returns None
        )delim"_doc,
        "type"_a, nb::rv_policy::reference_internal)

    .def("get_unauth_attribute",
        &SignerInfo::get_unauth_attribute,
        R"delim(
        Return the un-authenticated attribute matching the
        given :class:`lief.PE.SIG_ATTRIBUTE_TYPES`
        It returns **the first** entry that matches the given type. If it can't be
        found, it returns a nullptr
        )delim"_doc,
        "type"_a, nb::rv_policy::reference_internal)

    .def_prop_ro("cert",
        nb::overload_cast<>(&SignerInfo::cert),
        "" RST_CLASS_REF(lief.PE.x509) " certificate used by this signer. If it can't be found, it returns None"_doc,
        nb::rv_policy::reference_internal)

      LIEF_DEFAULT_STR(SignerInfo);
}

}

