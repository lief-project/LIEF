/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "enums_wrapper.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"

#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Signature::*)(void) const;

template<class T>
using setter_t = void (Signature::*)(T);


template<>
void create<Signature>(py::module& m) {

  py::class_<Signature, LIEF::Object> signature(m, "Signature");
  LIEF::enum_<Signature::VERIFICATION_FLAGS>(signature, "VERIFICATION_FLAGS", py::arithmetic())
    .value("OK",                            Signature::VERIFICATION_FLAGS::OK)
    .value("INVALID_SIGNER",                Signature::VERIFICATION_FLAGS::INVALID_SIGNER)
    .value("UNSUPPORTED_ALGORITHM",         Signature::VERIFICATION_FLAGS::UNSUPPORTED_ALGORITHM)
    .value("INCONSISTENT_DIGEST_ALGORITHM", Signature::VERIFICATION_FLAGS::INCONSISTENT_DIGEST_ALGORITHM)
    .value("CERT_NOT_FOUND",                Signature::VERIFICATION_FLAGS::CERT_NOT_FOUND)
    .value("CORRUPTED_CONTENT_INFO",        Signature::VERIFICATION_FLAGS::CORRUPTED_CONTENT_INFO)
    .value("CORRUPTED_AUTH_DATA",           Signature::VERIFICATION_FLAGS::CORRUPTED_AUTH_DATA)
    .value("MISSING_PKCS9_MESSAGE_DIGEST",  Signature::VERIFICATION_FLAGS::MISSING_PKCS9_MESSAGE_DIGEST)
    .value("BAD_DIGEST",                    Signature::VERIFICATION_FLAGS::BAD_DIGEST)
    .value("BAD_SIGNATURE",                 Signature::VERIFICATION_FLAGS::BAD_SIGNATURE)
    .value("NO_SIGNATURE",                  Signature::VERIFICATION_FLAGS::NO_SIGNATURE);

  signature
    .def_static("parse",
        [] (const std::string& path) -> py::object {
          auto sig = SignatureParser::parse(path);
          if (not sig) {
            return py::none();
          }
          return py::cast(sig.value());
        },
        "Parse the DER PKCS #7 signature from the file path given in the first parameter",
        "path"_a)

    .def_static("parse",
        [] (const std::vector<uint8_t>& raw, bool skip_header) -> py::object {
          auto sig = SignatureParser::parse(raw, skip_header);
          if (not sig) {
            return py::none();
          }
          return py::cast(sig.value());
        },
        "Parse the raw (DER) PKCS #7 signature given in the first parameter",
        "raw"_a, "skip_header"_a = false)

    .def_property_readonly("version",
        &Signature::version,
        "Should be 1")

    .def_property_readonly("digest_algorithm",
        &Signature::digest_algorithm,
        "Return the algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") \
        used to sign the content of " RST_CLASS_REF(lief.PE.ContentInfo) "")


    .def_property_readonly("content_info",
        &Signature::content_info,
        "Return the " RST_CLASS_REF(lief.PE.ContentInfo) "",
        py::return_value_policy::reference)


    .def_property_readonly("certificates",
        &Signature::certificates,
        "Return an iterator over " RST_CLASS_REF(lief.PE.x509) " certificates",
        py::return_value_policy::reference)


    .def_property_readonly("signers",
        &Signature::signers,
        "Return an iterator over the signers: " RST_CLASS_REF(lief.PE.SignerInfo) "",
        py::return_value_policy::reference)

    .def("check",
        &Signature::check,
        R"delim(
        Check the integrity of the signature and return a :class:`lief.PE.Signature.VERIFICATION_FLAGS`

        It performs the following verifications:

        1. It must contain only **one** signer info (:attr:`~lief.PE.Signature.signers`)
        2. :attr:`lief.PE.Signature.digest_algorithm` must match:

           * :attr:`lief.PE.ContentInfo.digest_algorithm`
           * :attr:`lief.PE.SignerInfo.digest_algorithm`

        3. The x509 certificate specified by :attr:`lief.PE.SignerInfo.serial_number` **and** :attr:`lief.PE.SignerInfo.issuer`
           must exist within :attr:`lief.PE.Signature.certificates`
        4. Given the x509 certificate, compare :attr:`lief.PE.SignerInfo.encrypted_digest` against either:

           * hash of authenticated attributes (:attr:`~lief.PE.SignerInfo.authenticated_attributes`) if present
           * hash of ContentInfo

        5. If they are Authenticated attributes, check that a PKCS9_MESSAGE_DIGEST (:class:`lief.PE.PKCS9MessageDigest`) attribute exists
           and that its value matches hash of ContentInfo

        )delim")

    .def_property_readonly("raw_der",
        [] (const Signature& sig) {
          const std::vector<uint8_t>& raw = sig.raw_der();
          return py::bytes(reinterpret_cast<const char*>(raw.data()), raw.size());
        },
        "Return the raw original signature as a byte object",
        py::return_value_policy::reference_internal)

    .def("__hash__",
        [] (const Signature& obj) {
          return Hash::hash(obj);
        })

    .def("__str__",
        [] (const Signature& signature)
        {
          std::ostringstream stream;
          stream << signature;
          return stream.str();
        });
}

}
}

