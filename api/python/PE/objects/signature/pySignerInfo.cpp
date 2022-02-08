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
#include <string>
#include <sstream>

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/signature/SignerInfo.hpp"
#include "LIEF/PE/signature/Attribute.hpp"

#include "pyPE.hpp"
#include "pyIterators.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (SignerInfo::*)(void) const;

template<class T>
using setter_t = void (SignerInfo::*)(T);


template<>
void create<SignerInfo>(py::module& m) {

  py::class_<SignerInfo, LIEF::Object> signer(m, "SignerInfo",
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
    )delim");


  init_ref_iterator<SignerInfo::it_const_attributes_t>(signer, "it_const_attributes_t");

  signer
    .def_property_readonly("version",
        &SignerInfo::version,
        "Should be 1")

    .def_property_readonly("serial_number",
        [] (const SignerInfo& info) -> py::bytes {
          const std::vector<uint8_t>& data = info.serial_number();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "The X509 serial number used to sign the signed-data (see: :attr:`lief.PE.x509.serial_number`)")

    .def_property_readonly("issuer",
        [] (const SignerInfo& object) {
          return safe_string_converter(object.issuer());
        },
        "The X509 issuer used to sign the signed-data (see: :attr:`lief.PE.x509.issuer`)",
        py::return_value_policy::copy)

    .def_property_readonly("digest_algorithm",
        &SignerInfo::digest_algorithm,
        "Algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") used to hash the file. "
        "This value should match " RST_ATTR_REF_FULL(ContentInfo.digest_algorithm) " "
        "and " RST_ATTR_REF_FULL(Signature.digest_algorithm) "")

    .def_property_readonly("encryption_algorithm",
        &SignerInfo::encryption_algorithm,
        "Return algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") used to encrypt the digest")

    .def_property_readonly("encrypted_digest",
        [] (const SignerInfo& info) {
          const std::vector<uint8_t>& data = info.encrypted_digest();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Return the signature created by the signing certificate's private key")

    .def_property_readonly("authenticated_attributes",
        &SignerInfo::authenticated_attributes,
        "Return an iterator over the authenticated attributes ("
        "" RST_CLASS_REF(lief.PE.Attribute) ")",
        py::return_value_policy::reference)

    .def_property_readonly("unauthenticated_attributes",
        &SignerInfo::unauthenticated_attributes,
        "Return an iterator over the unauthenticated attributes ("
        "" RST_CLASS_REF(lief.PE.Attribute) ")",
        py::return_value_policy::reference)

    .def("get_attribute",
        &SignerInfo::get_attribute,
        R"delim(
        Return the authenticated or un-authenticated attribute matching the
        given :class:`lief.PE.SIG_ATTRIBUTE_TYPES`
        It returns **the first** entry that matches the given type. If it can't be
        found, it returns None
        )delim",
        "type"_a,
        py::return_value_policy::reference)

    .def("get_auth_attribute",
        &SignerInfo::get_auth_attribute,
        R"delim(
        Return the authenticated attribute matching the
        given :class:`lief.PE.SIG_ATTRIBUTE_TYPES`
        It returns **the first** entry that matches the given type. If it can't be
        found, it returns None
        )delim",
        "type"_a,
        py::return_value_policy::reference)

    .def("get_unauth_attribute",
        &SignerInfo::get_unauth_attribute,
        R"delim(
        Return the un-authenticated attribute matching the
        given :class:`lief.PE.SIG_ATTRIBUTE_TYPES`
        It returns **the first** entry that matches the given type. If it can't be
        found, it returns a nullptr
        )delim",
        "type"_a,
        py::return_value_policy::reference)

    .def_property_readonly("cert",
        static_cast<x509*(SignerInfo::*)()>(&SignerInfo::cert),
        "" RST_CLASS_REF(lief.PE.x509) " certificate used by this signer. If it can't be found, it returns None",
        py::return_value_policy::reference)

    .def("__hash__",
        [] (const SignerInfo& obj) {
          return Hash::hash(obj);
        })

    .def("__str__",
        [] (const SignerInfo& signer_info)
        {
          std::ostringstream stream;
          stream << signer_info;
          std::string str =  stream.str();
          return str;
        });

}

}
}

