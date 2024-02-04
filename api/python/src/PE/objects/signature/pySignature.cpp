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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include "nanobind/utils.hpp"

#include "enums_wrapper.hpp"

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"

#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"

namespace LIEF::PE::py {

template<>
void create<Signature>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Signature, LIEF::Object> signature(m, "Signature");
  enum_<Signature::VERIFICATION_FLAGS> verif_flags_enums
    (signature, "VERIFICATION_FLAGS", nb::is_arithmetic());
  verif_flags_enums
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
    .value("NO_SIGNATURE",                  Signature::VERIFICATION_FLAGS::NO_SIGNATURE)
    .value("CERT_EXPIRED",                  Signature::VERIFICATION_FLAGS::CERT_EXPIRED)
    .value("CERT_FUTURE",                   Signature::VERIFICATION_FLAGS::CERT_FUTURE);

  enum_<Signature::VERIFICATION_CHECKS>(signature, "VERIFICATION_CHECKS", nb::is_arithmetic(),
    R"delim(
    Flags to tweak the verification process of the signature
    See :meth:`lief.PE.Signature.check` and :meth:`lief.PE.Binary.verify_signature`
    )delim"_doc)
    .value("DEFAULT", Signature::VERIFICATION_CHECKS::DEFAULT,
           "Default behavior that tries to follow the Microsoft verification process as close as possible"_doc)

    .value("HASH_ONLY", Signature::VERIFICATION_CHECKS::HASH_ONLY,
           R"delim(
           Only check that :meth:`lief.PE.Binary.authentihash` matches :attr:`lief.PE.ContentInfo.digest`
           regardless of the signature's validity
           )delim"_doc)

    .value("LIFETIME_SIGNING", Signature::VERIFICATION_CHECKS::LIFETIME_SIGNING,
           R"delim(
           Same semantic as `WTD_LIFETIME_SIGNING_FLAG <https://docs.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data#WTD_LIFETIME_SIGNING_FLAG>`_
           )delim"_doc)

    .value("SKIP_CERT_TIME", Signature::VERIFICATION_CHECKS::SKIP_CERT_TIME,
           R"delim(
           Skip the verification of the certificates time validities so that even though
           a certificate expired, it returns :attr:`lief.PE.Signature.VERIFICATION_FLAGS.OK`
           )delim"_doc);

  init_ref_iterator<Signature::it_const_crt>(signature, "it_const_crt");
  init_ref_iterator<Signature::it_const_signers_t>(signature, "it_const_signers_t");

  signature
    .def_static("parse",
        [] (const std::string& path) -> std::unique_ptr<Signature> {
          auto sig = SignatureParser::parse(path);
          if (!sig) {
            return nullptr;
          }
          return std::make_unique<Signature>(std::move(sig.value()));
        },
        "Parse the DER PKCS #7 signature from the file path given in the first parameter"_doc,
        "path"_a, nb::rv_policy::take_ownership)

    .def_static("parse",
        [] (const std::vector<uint8_t>& raw, bool skip_header) -> std::unique_ptr<Signature> {
          auto sig = SignatureParser::parse(raw, skip_header);
          if (!sig) {
            return nullptr;
          }
          return std::make_unique<Signature>(std::move(sig.value()));
        },
        "Parse the raw (DER) PKCS #7 signature given in the first parameter"_doc,
        "raw"_a, "skip_header"_a = false)

    .def_prop_ro("version",
        &Signature::version,
        "Version of the signature. It should be 1"_doc)

    .def_prop_ro("digest_algorithm",
        &Signature::digest_algorithm,
        "Return the algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") \
        used to sign the content of " RST_CLASS_REF(lief.PE.ContentInfo) ""_doc)

    .def_prop_ro("content_info",
        &Signature::content_info,
        "Return the " RST_CLASS_REF(lief.PE.ContentInfo) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("certificates",
        nb::overload_cast<>(&Signature::certificates, nb::const_),
        "Return an iterator over " RST_CLASS_REF(lief.PE.x509) " certificates"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("signers",
        nb::overload_cast<>(&Signature::signers, nb::const_),
        "Return an iterator over the signers (" RST_CLASS_REF(lief.PE.SignerInfo) ")"_doc,
        nb::keep_alive<0, 1>())

    .def("find_crt",
        nb::overload_cast<const std::vector<uint8_t>&>(&Signature::find_crt, nb::const_),
        "Find the " RST_CLASS_REF(lief.PE.x509) " certificate according to its serial number"_doc,
        nb::rv_policy::reference,
        "serialno"_a)

    .def("find_crt_subject",
        nb::overload_cast<const std::string&>(&Signature::find_crt_subject, nb::const_),
        "Find the " RST_CLASS_REF(lief.PE.x509) " certificate according to its subject"_doc,
        nb::rv_policy::reference,
        "subject"_a)

    .def("find_crt_subject",
        nb::overload_cast<const std::string&, const std::vector<uint8_t>&>(&Signature::find_crt_subject, nb::const_),
        "Find the " RST_CLASS_REF(lief.PE.x509) " certificate according to its subject **AND** its serial number"_doc,
        nb::rv_policy::reference,
        "subject"_a, "serialno"_a)

    .def("find_crt_issuer",
        nb::overload_cast<const std::string&>(&Signature::find_crt_issuer, nb::const_),
        "Find the " RST_CLASS_REF(lief.PE.x509) " certificate according to its issuer"_doc,
        nb::rv_policy::reference,
        "issuer"_a)

    .def("find_crt_issuer",
        nb::overload_cast<const std::string&, const std::vector<uint8_t>&>(&Signature::find_crt_issuer, nb::const_),
        "Find the " RST_CLASS_REF(lief.PE.x509) " certificate according to its issuer **AND** its serial number"_doc,
        nb::rv_policy::reference,
        "issuer"_a, "serialno"_a)

    .def("check",
        &Signature::check,
        // Note: This documentation needs to be sync with LIEF::PE::Signature::check
        R"delim(
        Check the integrity of the signature and return a :class:`lief.PE.Signature.VERIFICATION_FLAGS`

        By default, it performs the following verifications:

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
        6. Check the validity of the PKCS #9 counter signature if present
        7. If the signature doesn't embed a signing-time in the counter signature, check the certificate
           validity. (See :attr:`lief.PE.Signature.VERIFICATION_CHECKS.LIFETIME_SIGNING` and :attr:`lief.pe.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME`)

        See: :class:`lief.PE.Signature.VERIFICATION_CHECKS` to tweak the behavior

        )delim"_doc,
        "checks"_a = Signature::VERIFICATION_CHECKS::DEFAULT
    )

    .def_prop_ro("raw_der",
        [] (const Signature& sig) {
          return nb::to_memoryview(sig.raw_der());
        },
        "Return the raw original signature as a byte object"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(Signature);
}

}
