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
#include <iomanip>
#include <fstream>

#include "logging.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/attributes.hpp"

#include <mbedtls/asn1write.h>

#include <mbedtls/sha512.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>

#include <mbedtls/md2.h>
#include <mbedtls/md4.h>
#include <mbedtls/md5.h>

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509.h"


namespace LIEF {
namespace PE {

inline std::string time_to_string(const x509::date_t& date) {
  return fmt::format("{:d}/{:02d}/{:02d} - {:02d}:{:02d}:{:02d}",
      date[0], date[1], date[2],
      date[3], date[4], date[5]);
}


Signature::VERIFICATION_FLAGS verify_ts_counter_signature(const SignerInfo& signer,
    const PKCS9CounterSignature& cs, Signature::VERIFICATION_CHECKS checks) {
  LIEF_DEBUG("PKCS #9 Counter signature found");
  Signature::VERIFICATION_FLAGS flags = Signature::VERIFICATION_FLAGS::OK;
   const SignerInfo& cs_signer = cs.signer();
  if (cs_signer.cert() == nullptr) {
    LIEF_WARN("Can't find x509 certificate associated with Counter Signature's signer");
    return flags | Signature::VERIFICATION_FLAGS::CERT_NOT_FOUND;
  }
  const x509& cs_cert = *cs_signer.cert();
  const SignerInfo::encrypted_digest_t& cs_enc_digest = cs_signer.encrypted_digest();

  std::vector<uint8_t> cs_auth_data = cs_signer.raw_auth_data();
  // According to the RFC:
  //
  // "[...] The Attributes value's tag is SET OF, and the DER encoding of
  // the SET OF tag, rather than of the IMPLICIT [0] tag [...]"
  cs_auth_data[0] = /* SET OF */ 0x31;
  const ALGORITHMS cs_digest_algo = cs_signer.digest_algorithm();
  const std::vector<uint8_t>& cs_hash = Signature::hash(cs_auth_data, cs_digest_algo);
  LIEF_DEBUG("Signed data digest: {}", hex_dump(cs_hash));
  bool check_sig = cs_cert.check_signature(cs_hash, cs_enc_digest, cs_digest_algo);

  if (not check_sig) {
    LIEF_WARN("Authenticated signature (counter signature) mismatch");
    //return flags | VERIFICATION_FLAGS::BAD_SIGNATURE;
  }


  /* According to Microsoft documentation:
   * The Authenticode timestamp SignerInfo structure contains the following authenticated attributes values:
   * 1. ContentType (1.2.840.113549.1.9.3) is set to PKCS #7 Data (1.2.840.113549.1.7.1).
   * 2. Signing Time (1.2.840.113549.1.9.5) is set to the UTC time of timestamp generation time.
   * 3. Message Digest (1.2.840.113549.1.9.4) is set to the hash value of the
   *    SignerInfo structure's encryptedDigest value. The hash algorithm that
   *    is used to calculate the hash value is the same as that specified in the
   *    SignerInfo structure’s digestAlgorithm value of the timestamp.
   */

  // Verify 1.
  const auto* content_type_data = reinterpret_cast<const ContentType*>(cs_signer.get_auth_attribute(SIG_ATTRIBUTE_TYPES::CONTENT_TYPE));
  if (content_type_data == nullptr) {
    LIEF_WARN("Missing ContentType in authenticated attributes in the counter signature's signer");
    return flags | Signature::VERIFICATION_FLAGS::INVALID_SIGNER;
  }

  if (content_type_data->oid() != /* PKCS #7 Data */ "1.2.840.113549.1.7.1") {
    LIEF_WARN("Bad OID for ContentType in authenticated attributes in the counter signature's signer ({})",
               content_type_data->oid());
    return flags | Signature::VERIFICATION_FLAGS::INVALID_SIGNER;
  }

  // Verify 3.
  const auto* message_dg = reinterpret_cast<const PKCS9MessageDigest*>(cs_signer.get_auth_attribute(SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST));
  if (message_dg == nullptr) {
    LIEF_WARN("Missing MessageDigest in authenticated attributes in the counter signature's signer");
    return flags | Signature::VERIFICATION_FLAGS::INVALID_SIGNER;
  }
  const std::vector<uint8_t>& dg_value = message_dg->digest();
  const std::vector<uint8_t> dg_cs_hash = Signature::hash(signer.encrypted_digest(), cs_digest_algo);
  if (dg_value != dg_cs_hash) {
    LIEF_WARN("MessageDigest mismatch with Hash(signer ED)");
    return flags | Signature::VERIFICATION_FLAGS::INVALID_SIGNER;
  }

  /*
   * Verify that signing's time is valid within the signer's certificate
   * validity window.
   */
  const auto* signing_time = reinterpret_cast<const PKCS9SigningTime*>(cs_signer.get_auth_attribute(SIG_ATTRIBUTE_TYPES::PKCS9_SIGNING_TIME));
  if (signing_time != nullptr and not is_true(checks & Signature::VERIFICATION_CHECKS::SKIP_CERT_TIME)) {
    LIEF_DEBUG("PKCS #9 signing time found");
    PKCS9SigningTime::time_t time = signing_time->time();
    if (not x509::check_time(time, cs_cert.valid_to())) {
      LIEF_WARN("Signing time: {} is above the certificate validity: {}",
          time_to_string(time), time_to_string(cs_cert.valid_to()));
      return flags | Signature::VERIFICATION_FLAGS::CERT_EXPIRED;
    }

    if (not x509::check_time(cs_cert.valid_from(), time)) {
      LIEF_WARN("Signing time: {} is below the certificate validity: {}",
          time_to_string(time), time_to_string(cs_cert.valid_to()));
      return flags | Signature::VERIFICATION_FLAGS::CERT_FUTURE;
    }
  }
  return flags;
}


Signature::Signature(void) = default;
Signature::Signature(const Signature&) = default;
Signature& Signature::operator=(const Signature&) = default;
Signature::~Signature(void) = default;


std::vector<uint8_t> Signature::hash(const std::vector<uint8_t>& input, ALGORITHMS algo) {
  switch (algo) {

    case ALGORITHMS::SHA_512:
      {
        std::vector<uint8_t> out(64);
        int ret = mbedtls_sha512_ret(input.data(), input.size(), out.data(), /* is384 */ false);
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with SHA-512 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    case ALGORITHMS::SHA_384:
      {
        std::vector<uint8_t> out(64);
        int ret = mbedtls_sha512_ret(input.data(), input.size(), out.data(), /* is384 */ true);
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with SHA-384 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    case ALGORITHMS::SHA_256:
      {
        std::vector<uint8_t> out(32);
        int ret = mbedtls_sha256_ret(input.data(), input.size(), out.data(), /* is224 */ false);
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with SHA-256 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    case ALGORITHMS::SHA_1:
      {
        std::vector<uint8_t> out(20);
        int ret = mbedtls_sha1_ret(input.data(), input.size(), out.data());
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with SHA-1 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    case ALGORITHMS::MD5:
      {
        std::vector<uint8_t> out(16);
        int ret = mbedtls_md5_ret(input.data(), input.size(), out.data());
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with MD5 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    case ALGORITHMS::MD4:
      {
        std::vector<uint8_t> out(16);
        int ret = mbedtls_md4_ret(input.data(), input.size(), out.data());
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with MD4 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    case ALGORITHMS::MD2:
      {
        std::vector<uint8_t> out(16);
        int ret = mbedtls_md2_ret(input.data(), input.size(), out.data());
        if (ret != 0) {
          LIEF_ERR("Hashing {} bytes with MD2 failed! (ret: 0x{:x})", input.size(), ret);
          return {};
        }
        return out;
      }

    default:
      {
        LIEF_ERR("Unsupported hash algorithm {}", to_string(algo));
      }
  }
  return {};
}

uint32_t Signature::version(void) const {
  return this->version_;
}


const ContentInfo& Signature::content_info(void) const {
  return this->content_info_;
}

it_const_crt Signature::certificates(void) const {
  return this->certificates_;
}

it_const_signers_t Signature::signers(void) const {
  return this->signers_;
}

Signature::VERIFICATION_FLAGS Signature::check(VERIFICATION_CHECKS checks) const {
  // According to the Authenticode documentation,
  // *SignerInfos contains one SignerInfo structure*
  const size_t nb_signers = this->signers_.size();
  VERIFICATION_FLAGS flags = VERIFICATION_FLAGS::OK;
  if (nb_signers == 0) {
    LIEF_WARN("No signer associated with the signature");
    return flags | VERIFICATION_FLAGS::INVALID_SIGNER;
  }

  if (nb_signers > 1) {
    LIEF_WARN("More than ONE signer ({:d} signers)", nb_signers);
    return flags | VERIFICATION_FLAGS::INVALID_SIGNER;
  }
  const SignerInfo& signer = this->signers_.back();

  // Check that Signature.digest_algorithm matches:
  // - SignerInfo.digest_algorithm
  // - ContentInfo.digest_algorithm

  if (this->digest_algorithm_ == ALGORITHMS::UNKNOWN) {
    LIEF_WARN("Unsupported digest algorithm");
    return flags | VERIFICATION_FLAGS::UNSUPPORTED_ALGORITHM;
  }

  if (this->digest_algorithm_ != this->content_info_.digest_algorithm()) {
    LIEF_WARN("Digest algorithm is different from ContentInfo");
    return flags | VERIFICATION_FLAGS::INCONSISTENT_DIGEST_ALGORITHM;
  }

  if (this->digest_algorithm_ != signer.digest_algorithm()) {
    LIEF_WARN("Digest algorithm is different from Signer");
    return flags | VERIFICATION_FLAGS::INCONSISTENT_DIGEST_ALGORITHM;
  }

  const ALGORITHMS digest_algo = this->content_info().digest_algorithm();

  if (signer.cert() == nullptr) {
    LIEF_WARN("Can't find certificate whose the issuer is {}", signer.issuer());
    return flags | VERIFICATION_FLAGS::CERT_NOT_FOUND;
  }
  const x509& cert = *signer.cert();
  const SignerInfo::encrypted_digest_t& enc_digest = signer.encrypted_digest();

  /*
   * Check the following condition:
   *  "The signing certificate must contain either the extended key usage (EKU)
   *   value for code signing, or the entire certificate chain must contain no
   *   EKUs. The following is the EKU value for code signing"
   */
  //TODO(romain)

  /*
   * Verify certificate validity
   */

  if (this->content_info_start_ == 0 or this->content_info_end_ == 0) {
    return flags | VERIFICATION_FLAGS::CORRUPTED_CONTENT_INFO;
  }

  std::vector<uint8_t> raw_content_info = {
    std::begin(this->original_raw_signature_) + this->content_info_start_,
    std::begin(this->original_raw_signature_) + this->content_info_end_
  };

  const std::vector<uint8_t> content_info_hash = Signature::hash(std::move(raw_content_info), digest_algo);


  // Copy authenticated attributes
  it_const_attributes_t auth_attrs = signer.authenticated_attributes();
  if (auth_attrs.size() > 0) {

    std::vector<uint8_t> auth_data = signer.raw_auth_data_;
    // According to the RFC:
    //
    // "[...] The Attributes value's tag is SET OF, and the DER encoding of
    // the SET OF tag, rather than of the IMPLICIT [0] tag [...]"
    auth_data[0] = /* SET OF */ 0x31;

    const std::vector<uint8_t> auth_attr_hash = Signature::hash(auth_data, digest_algo);
    LIEF_DEBUG("Authenticated attribute digest: {}", hex_dump(auth_attr_hash));
    bool check_sig = cert.check_signature(auth_attr_hash, enc_digest, digest_algo);

    if (not check_sig) {
      LIEF_WARN("Authenticated signature mismatch");
      return flags | VERIFICATION_FLAGS::BAD_SIGNATURE;
    }

    // Check that content_info_hash matches pkcs9-message-digest
    auto it_pkcs9_digest = std::find_if(std::begin(auth_attrs), std::end(auth_attrs),
        [] (const Attribute& attr) {
          return attr.type() == SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST;
        });

    if (it_pkcs9_digest == std::end(auth_attrs)) {
      LIEF_WARN("Can't find the authenticated attribute: 'pkcs9-message-digest'");
      return flags | VERIFICATION_FLAGS::MISSING_PKCS9_MESSAGE_DIGEST;
    }

    const auto& digest_attr = reinterpret_cast<const PKCS9MessageDigest&>(*it_pkcs9_digest);
    LIEF_DEBUG("pkcs9-message-digest:\n  {}\n  {}", hex_dump(digest_attr.digest()), hex_dump(content_info_hash));
    if (digest_attr.digest() != content_info_hash) {
      return flags | VERIFICATION_FLAGS::BAD_DIGEST;
    }
  } else {
    /*
     * If there is no authenticated attributes, then the encrypted digested should match ENC(content_info_hash)
     */
    if (not cert.check_signature(content_info_hash, enc_digest, digest_algo)) {
      return flags | VERIFICATION_FLAGS::BAD_SIGNATURE;
    }
  }

  /*
   * CounterSignature Checks
   */
  const auto* counter = reinterpret_cast<const PKCS9CounterSignature*>(signer.get_unauth_attribute(SIG_ATTRIBUTE_TYPES::PKCS9_COUNTER_SIGNATURE));
  bool has_ms_counter_sig = false;
  for (const Attribute& attr : signer.unauthenticated_attributes()) {
    if (attr.type() == SIG_ATTRIBUTE_TYPES::GENERIC_TYPE) {
      if (reinterpret_cast<const GenericType&>(attr).oid() == /* Ms-CounterSign */ "1.3.6.1.4.1.311.3.3.1") {
        has_ms_counter_sig = true;
        break;
      }
    }
  }
  bool timeless_signature = false;
  if (counter != nullptr) {
    VERIFICATION_FLAGS cs_flags = verify_ts_counter_signature(signer, *counter, checks);
    if (cs_flags == VERIFICATION_FLAGS::OK) {
      timeless_signature = true;
    }
  } else if (not timeless_signature and has_ms_counter_sig) {
    timeless_signature = true;
  }
  bool should_check_cert_time = not timeless_signature or is_true(checks & VERIFICATION_CHECKS::LIFETIME_SIGNING);
  if (is_true(checks & VERIFICATION_CHECKS::SKIP_CERT_TIME)) {
      should_check_cert_time = false;
  }
  if (should_check_cert_time) {
    /*
     * Verify certificate validities
     */
    if (x509::time_is_past(cert.valid_to())) {
      return flags | VERIFICATION_FLAGS::CERT_EXPIRED;
    }

    if (x509::time_is_future(cert.valid_from())) {
      return flags | VERIFICATION_FLAGS::CERT_FUTURE;
    }

  }
  return flags;
}


const std::vector<uint8_t>& Signature::raw_der(void) const {
  return this->original_raw_signature_;
}


const x509* Signature::find_crt(const std::vector<uint8_t>& serialno) const {
  auto it_cert = std::find_if(std::begin(this->certificates_), std::end(this->certificates_),
      [&serialno] (const x509& cert) {
        return cert.serial_number() == serialno;
      });
  if (it_cert == std::end(this->certificates_)) {
    return nullptr;
  }
  return &(*it_cert);
}


const x509* Signature::find_crt_subject(const std::string& subject) const {
  auto it_cert = std::find_if(std::begin(this->certificates_), std::end(this->certificates_),
      [&subject] (const x509& cert) {
        return cert.subject() == subject;
      });
  if (it_cert == std::end(this->certificates_)) {
    return nullptr;
  }
  return &(*it_cert);
}

const x509* Signature::find_crt_subject(const std::string& subject, const std::vector<uint8_t>& serialno) const {
  auto it_cert = std::find_if(std::begin(this->certificates_), std::end(this->certificates_),
      [&subject, &serialno] (const x509& cert) {
        return cert.subject() == subject and cert.serial_number() == serialno;
      });
  if (it_cert == std::end(this->certificates_)) {
    return nullptr;
  }
  return &(*it_cert);
}

const x509* Signature::find_crt_issuer(const std::string& issuer) const {
  auto it_cert = std::find_if(std::begin(this->certificates_), std::end(this->certificates_),
      [&issuer] (const x509& cert) {
        return cert.issuer() == issuer;
      });
  if (it_cert == std::end(this->certificates_)) {
    return nullptr;
  }
  return &(*it_cert);
}

const x509* Signature::find_crt_issuer(const std::string& issuer, const std::vector<uint8_t>& serialno) const {
  auto it_cert = std::find_if(std::begin(this->certificates_), std::end(this->certificates_),
      [&issuer, &serialno] (const x509& cert) {
        return cert.issuer() == issuer and cert.serial_number() == serialno;
      });
  if (it_cert == std::end(this->certificates_)) {
    return nullptr;
  }
  return &(*it_cert);
}

void Signature::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

inline void print_attr(it_const_attributes_t& attrs, std::ostream& os) {
  for (const Attribute& attr : attrs) {
    std::string suffix;
    switch (attr.type()) {
      case SIG_ATTRIBUTE_TYPES::CONTENT_TYPE:
        {
          const auto& ct = reinterpret_cast<const ContentType&>(attr);
          suffix = ct.oid() + " (" + oid_to_string(ct.oid()) + ")";
          break;
        }

      case SIG_ATTRIBUTE_TYPES::MS_SPC_STATEMENT_TYPE:
        {
          const auto& ct = reinterpret_cast<const MsSpcStatementType&>(attr);
          suffix = ct.oid() + " (" + oid_to_string(ct.oid()) + ")";
          break;
        }

      case SIG_ATTRIBUTE_TYPES::SPC_SP_OPUS_INFO:
        {
          const auto& ct = reinterpret_cast<const SpcSpOpusInfo&>(attr);
          if (not ct.program_name().empty()) {
            suffix = ct.program_name();
          }
          if (not ct.more_info().empty()) {
            if (not suffix.empty()) {
              suffix += " - ";
            }
            suffix += ct.more_info();
          }
          break;
        }

      case SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST:
        {
          const auto& ct = reinterpret_cast<const PKCS9MessageDigest&>(attr);
          suffix = hex_dump(ct.digest()).substr(0, 41) + "...";
          break;
        }

      case SIG_ATTRIBUTE_TYPES::MS_SPC_NESTED_SIGN:
        {
          const auto& nested_attr = reinterpret_cast<const MsSpcNestedSignature&>(attr);
          const Signature& ct = nested_attr.sig();
          auto signers = ct.signers();
          auto crts = ct.certificates();
          if (signers.size() > 0) {
            suffix = signers[0].issuer();
          } else if (crts.size() > 0) {
            suffix = crts[0].issuer();
          }
          break;
        }

      case SIG_ATTRIBUTE_TYPES::GENERIC_TYPE:
        {
          const auto& ct = reinterpret_cast<const GenericType&>(attr);
          suffix = ct.oid();
          break;
        }

      case SIG_ATTRIBUTE_TYPES::PKCS9_AT_SEQUENCE_NUMBER:
        {
          const auto& ct = reinterpret_cast<const PKCS9AtSequenceNumber&>(attr);
          suffix = std::to_string(ct.number());
          break;
        }

      case SIG_ATTRIBUTE_TYPES::PKCS9_COUNTER_SIGNATURE:
        {
          const auto& ct = reinterpret_cast<const PKCS9CounterSignature&>(attr);
          const SignerInfo& signer = ct.signer();
          suffix = signer.issuer();
          break;
        }

      case SIG_ATTRIBUTE_TYPES::PKCS9_SIGNING_TIME:
        {
          const auto& ct = reinterpret_cast<const PKCS9SigningTime&>(attr);
          const PKCS9SigningTime::time_t time = ct.time();
          suffix = fmt::format("{}/{}/{} - {}:{}:{}",
                              time[0], time[1], time[2], time[3], time[4], time[5]);
          break;
        }

      default:
        {
        }
    }
    os << fmt::format("  {}: {}\n", to_string(attr.type()), suffix);

  }
}

std::ostream& operator<<(std::ostream& os, const Signature& signature) {
  const ContentInfo& cinfo = signature.content_info();
  os << fmt::format("Version:             {:d}\n", signature.version());
  os << fmt::format("Digest Algorithm:    {}\n", to_string(signature.digest_algorithm()));
  os << fmt::format("Content Info Digest: {}\n", hex_dump(cinfo.digest()));
  if (not cinfo.file().empty()) {
    os << fmt::format("Content Info File:   {}\n", cinfo.file());
  }
  it_const_crt certs = signature.certificates();
  os << fmt::format("#{:d} certificate(s):\n", certs.size());
  for (const x509& crt : certs) {
    os << fmt::format("  - {}\n", crt.issuer()); // TODO(romain): RSA-2048, ...
  }

  it_const_signers_t signers = signature.signers();
  os << fmt::format("#{:d} signer(s):\n", signers.size());
  for (const SignerInfo& signer : signers) {
    os << fmt::format("Issuer:       {}\n", signer.issuer());
    os << fmt::format("Digest:       {}\n", to_string(signer.digest_algorithm()));
    os << fmt::format("Encryption:   {}\n", to_string(signer.encryption_algorithm()));
    os << fmt::format("Encrypted DG: {} ...\n", hex_dump(signer.encrypted_digest()).substr(0, 41));
    it_const_attributes_t auth_attr = signer.authenticated_attributes();
    if (auth_attr.size() > 0) {
      os << fmt::format("#{:d} authenticated attributes:\n", auth_attr.size());
      print_attr(auth_attr, os);
    }

    it_const_attributes_t unauth_attr = signer.unauthenticated_attributes();
    if (unauth_attr.size() > 0) {
      os << fmt::format("#{:d} un-authenticated attributes:\n", unauth_attr.size());
      print_attr(unauth_attr, os);
    }

  }
  return os;
}


}
}
