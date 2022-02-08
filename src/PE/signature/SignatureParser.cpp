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

#include <cstring>
#include <fstream>
#include <memory>

#include <mbedtls/platform.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "LIEF/utils.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/utils.hpp"

#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/signature/Signature.hpp"

#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/attributes/ContentType.hpp"
#include "LIEF/PE/signature/attributes/GenericType.hpp"
#include "LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"
#include "LIEF/PE/signature/attributes/PKCS9CounterSignature.hpp"
#include "LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"
#include "LIEF/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"
#include "LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"
#include "LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"
#include "LIEF/PE/signature/attributes/MsSpcStatementType.hpp"

#include "LIEF/PE/signature/OIDToString.hpp"

#include "third-party/utfcpp.hpp"
#include "logging.hpp"
#include "pkcs7.h"

namespace LIEF {
namespace PE {

inline uint8_t stream_get_tag(VectorStream& stream) {
  auto tag = stream.peek<uint8_t>();
  if (tag) {
    return *tag;
  }
  return 0;
}

SignatureParser::~SignatureParser() = default;
SignatureParser::SignatureParser() = default;

SignatureParser::SignatureParser(std::vector<uint8_t> data) :
  stream_{std::make_unique<VectorStream>(std::move(data))}
{}

result<Signature> SignatureParser::parse(const std::string& path) {
  std::ifstream binary(path, std::ios::in | std::ios::binary);
  if (!binary) {
    LIEF_ERR("Can't open {}", path);
    return make_error_code(lief_errors::file_error);
  }
  binary.unsetf(std::ios::skipws);
  binary.seekg(0, std::ios::end);
  const auto size = static_cast<uint64_t>(binary.tellg());
  binary.seekg(0, std::ios::beg);
  std::vector<uint8_t> raw_blob(size, 0);
  binary.read(reinterpret_cast<char*>(raw_blob.data()), size);
  return SignatureParser::parse(std::move(raw_blob));
}

result<Signature> SignatureParser::parse(std::vector<uint8_t> data, bool skip_header) {
  if (data.size() < 10) {
    return make_error_code(lief_errors::read_error);
  }
  std::vector<uint8_t> sig_data = skip_header ?
    std::vector<uint8_t>{std::begin(data) + 8, std::end(data)} :
    /* else */
    std::move(data);

  SignatureParser parser{std::move(sig_data)};
  auto sig = parser.parse_signature();
  if (!sig) {
    LIEF_ERR("Error while parsing the signature");
    return sig.error();
  }
  return sig.value();
}

size_t SignatureParser::current_offset() const {
  return stream_->pos();
}


result<Signature> SignatureParser::parse_signature() {
  Signature signature;
  signature.original_raw_signature_ = stream_->content();
  auto tag = stream_->asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})",
        stream_get_tag(*stream_), stream_->pos());
    return tag.error();
  }

  auto oid = stream_->asn1_read_oid();
  if (!oid) {
    LIEF_INFO("Can't read OID value (pos: {})", stream_->pos());
    return oid.error();
  }
  std::string& oid_str = oid.value();

  if (oid_str != /* pkcs7-signedData */ "1.2.840.113549.1.7.2") {
    LIEF_INFO("Expecting OID pkcs7-signed-data at {:d} but got {}",
        stream_->pos(), oid_to_string(oid_str));
    return make_error_code(lief_errors::read_error);
  }

  tag = stream_->asn1_read_tag(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})",
        stream_get_tag(*stream_), stream_->pos());
    return tag.error();
  }
  tag = stream_->asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})",
        stream_get_tag(*stream_), stream_->pos());
    return tag.error();
  }

  /*
   * Defined in https://tools.ietf.org/html/rfc2315
   * SignedData ::= SEQUENCE {
   *   version          Version,
   *   digestAlgorithms DigestAlgorithmIdentifiers,
   *   contentInfo      ContentInfo,
   *   certificates
   *     [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
   *   crls
   *     [1] IMPLICIT CertificateRevocationLists OPTIONAL,
   *   signerInfos SignerInfos
   * }
   *
   * Version ::= INTEGER
   * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
   * SignerInfos ::= SET OF SignerInfo
   *
   *
   * SignerInfo ::= SEQUENCE {
   *      version Version,
   *      issuerAndSerialNumber IssuerAndSerialNumber,
   *      digestAlgorithm DigestAlgorithmIdentifier,
   *      authenticatedAttributes
   *        [0] IMPLICIT Attributes OPTIONAL,
   *      digestEncryptionAlgorithm
   *        DigestEncryptionAlgorithmIdentifier,
   *      encryptedDigest EncryptedDigest,
   *      unauthenticatedAttributes
   *        [1] IMPLICIT Attributes OPTIONAL
   * }
   *
   */

  // ==============================================================================
  // Version
  //
  // Version ::= INTEGER
  // ==============================================================================
  auto version = stream_->asn1_read_int();
  if (!version) {
    LIEF_INFO("Can't parse version (pos: {:d})", stream_->pos());
    return tag.error();
  }
  const int32_t version_val = version.value();
  LIEF_DEBUG("pkcs7-signed-data.version: {:d}", version_val);
  if (version_val != 1) {
    LIEF_INFO("pkcs7-signed-data.version is not 1 ({:d})", version_val);
    return make_error_code(lief_errors::not_supported);
  }
  signature.version_ = version_val;

  // ==============================================================================
  // Digest Algorithms
  //
  // DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
  // ==============================================================================
  tag = stream_->asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})",
        stream_get_tag(*stream_), stream_->pos());
    return tag.error();
  }
  const uintptr_t end_set = stream_->pos() + tag.value();
  std::vector<oid_t> algorithms;
  while (stream_->pos() < end_set) {
    const size_t current_p = stream_->pos();
    auto alg = stream_->asn1_read_alg();
    if (!alg) {
      LIEF_INFO("Can't parse signed data digest algorithm (pos: {:d})", stream_->pos());
      break;
    }
    if (stream_->pos() == current_p) {
      break;
    }
    LIEF_DEBUG("pkcs7-signed-data.digest-algorithms: {}", oid_to_string(alg.value()));
    algorithms.push_back(std::move(alg.value()));
  }

  if (algorithms.empty()) {
    LIEF_INFO("pkcs7-signed-data.digest-algorithms no algorithms found");
    return make_error_code(lief_errors::read_error);
  }

  if (algorithms.size() > 1) {
    LIEF_INFO("pkcs7-signed-data.digest-algorithms {:d} algorithms found. Expecting only 1", algorithms.size());
    return make_error_code(lief_errors::read_error);
  }

  ALGORITHMS algo = algo_from_oid(algorithms.back());
  if (algo == ALGORITHMS::UNKNOWN) {
    LIEF_WARN("LIEF does not handle algorithm {}", algorithms.back());
  } else {
    signature.digest_algorithm_ = algo;
  }


  // Content Info
  // =========================================================
  tag = stream_->asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} can't parse content info (pos: {:d})",
              stream_get_tag(*stream_), stream_->pos());
    return tag.error();
  }

  /* Content Info */ {
    std::vector<uint8_t> raw_content_info = {stream_->p(), stream_->p() + tag.value()};
    const size_t raw_content_size = raw_content_info.size();
    VectorStream content_info_stream{std::move(raw_content_info)};

    range_t range = {0, 0};
    auto content_info = parse_content_info(content_info_stream, range);
    if (!content_info) {
      LIEF_INFO("Fail to parse pkcs7-signed-data.content-info");
    } else {
      signature.content_info_ = *content_info;
      signature.content_info_start_ = stream_->pos() + range.start;
      signature.content_info_end_   = stream_->pos() + range.end;
      LIEF_DEBUG("ContentInfo range: {:d} -> {:d}",
                 signature.content_info_start_, signature.content_info_end_);
    }
    stream_->increment_pos(raw_content_size);
  }

  // X509 Certificates (optional)
  // =========================================================

  tag = stream_->asn1_read_tag(/* certificates */
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
  if (tag) {
    LIEF_DEBUG("Parse pkcs7-signed-data.certificates offset: {:d}", stream_->pos());
    std::vector<uint8_t> raw_content = {stream_->p(), stream_->p() + tag.value()};

    stream_->increment_pos(raw_content.size());
    VectorStream certificate_stream{std::move(raw_content)};

    auto certificates = parse_certificates(certificate_stream);
    if (!certificates) {
      LIEF_INFO("Fail to parse pkcs7-signed-data.certificates");
    } else {
      // Makes chain
      std::vector<x509> certs = certificates.value();
      signature.certificates_ = std::move(certs);
    }
  }

  // CRLS (optional)
  // =========================================================
  tag = stream_->asn1_read_tag(/* certificates */
                                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1);
  if (tag) {
    LIEF_DEBUG("Parse pkcs7-signed-data.crls offset: {:d}", stream_->pos());
    std::vector<uint8_t> raw_content = {stream_->p(), stream_->p() + tag.value()};
    // TODO(romain): Process crls certificates
    stream_->increment_pos(raw_content.size());
  }

  // SignerInfos
  // =========================================================
  tag = stream_->asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
  if (tag) {
    LIEF_DEBUG("Parse pkcs7-signed-data.signer-infos offset: {:d}", stream_->pos());
    std::vector<uint8_t> raw_content = {stream_->p(), stream_->p() + tag.value()};
    const size_t raw_content_size = raw_content.size();
    VectorStream stream{std::move(raw_content)};
    stream_->increment_pos(raw_content_size);
    auto signer_info = parse_signer_infos(stream);
    if (!signer_info) {
      LIEF_INFO("Fail to parse pkcs7-signed-data.signer-infos");
    } else {
      signature.signers_ = std::move(signer_info.value());
    }
  }

  // Tied signer info with x509 certificates
  for (SignerInfo& signer : signature.signers_) {
    const x509* crt = signature.find_crt_issuer(signer.issuer(), signer.serial_number());
    if (crt != nullptr) {
      signer.cert_ = std::make_unique<x509>(*crt);
    } else {
      LIEF_INFO("Can't find x509 certificate associated with signer '{}'", signer.issuer());
    }
    const auto* cs = static_cast<const PKCS9CounterSignature*>(signer.get_attribute(SIG_ATTRIBUTE_TYPES::PKCS9_COUNTER_SIGNATURE));
    if (cs != nullptr) {
      SignerInfo& cs_signer = const_cast<PKCS9CounterSignature*>(cs)->signer_;
      const x509* crt = signature.find_crt_issuer(cs_signer.issuer(), cs_signer.serial_number());
      if (crt != nullptr) {
        cs_signer.cert_ = std::make_unique<x509>(*crt);
      } else {
        LIEF_INFO("Can't find x509 certificate associated with signer '{}'", signer.issuer());
      }
    }
  }

  return signature;
}

result<ContentInfo> SignatureParser::parse_content_info(VectorStream& stream, range_t& range) {
  // ==============================================================================
  // ContentInfo
  // ContentInfo ::= SEQUENCE {
  //   contentType ContentType,
  //   content
  //     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
  // }
  // ContentType ::= OBJECT IDENTIFIER
  // ==============================================================================
  ContentInfo content_info;

  // First, process contentType which must match SPC_INDIRECT_DATA_CONTEXT
  {
    auto content_type = stream.asn1_read_oid();
    if (!content_type) {
      LIEF_INFO("Can't parse content-info.content-type (pos: {:d})", stream.pos());
      return content_type.error();
    }
    const std::string& ctype_str = content_type.value();
    LIEF_DEBUG("content-info.content-type: {}", oid_to_string(ctype_str));
    if (ctype_str != /* SPC_INDIRECT_DATA_CONTEXT */ "1.3.6.1.4.1.311.2.1.4") {
      LIEF_WARN("Expecting OID SPC_INDIRECT_DATA_CONTEXT at {:d} but got {}",
                stream.pos(), oid_to_string(ctype_str));
      return make_error_code(lief_errors::read_error);
    }
    content_info.content_type_ = ctype_str;
  }


  // ==============================================================================
  // Then process SpcIndirectDataContent, which has this structure:
  //
  // SpcIndirectDataContent ::= SEQUENCE {
  //  data          SpcAttributeTypeAndOptionalValue,
  //  messageDigest DigestInfo
  // }
  //
  // SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
  //  type  ObjectID, // Should be SPC_PE_IMAGE_DATA
  //  value [0] EXPLICIT ANY OPTIONAL
  // }
  //
  // DigestInfo ::= SEQUENCE {
  //  digestAlgorithm  AlgorithmIdentifier,
  //  digest           OCTETSTRING
  // }
  //
  // AlgorithmIdentifier ::= SEQUENCE {
  //  algorithm  ObjectID,
  //  parameters [0] EXPLICIT ANY OPTIONAL
  // }
  // ==============================================================================
  auto tag = stream.asn1_read_tag(/* [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL */
                                  MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})", stream_get_tag(stream), stream.pos());
    return tag.error();
  }
  range.end   = stream.size();

  tag = stream.asn1_read_tag(/* SpcIndirectDataContent */
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})", stream_get_tag(stream), stream.pos());
    return tag.error();
  }

  range.start = stream.pos();
  tag = stream.asn1_read_tag(/* SpcAttributeTypeAndOptionalValue */
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})", stream_get_tag(stream), stream.pos());
    return tag.error();
  }

  // SpcAttributeTypeAndOptionalValue.type
  auto spc_attr_type = stream.asn1_read_oid();
  if (!spc_attr_type) {
    LIEF_INFO("Can't parse spc-attribute-type-and-optional-value.type (pos: {:d})", stream.pos());
    return spc_attr_type.error();
  }
  const std::string& spc_attr_type_str = spc_attr_type.value();
  LIEF_DEBUG("spc-attribute-type-and-optional-value.type: {}", oid_to_string(spc_attr_type_str));
  if (spc_attr_type_str != /* SPC_PE_IMAGE_DATA */ "1.3.6.1.4.1.311.2.1.15") {
    LIEF_WARN("Expecting OID SPC_PE_IMAGE_DATA at {:d} but got {}",
              stream.pos(), oid_to_string(spc_attr_type_str));
    return make_error_code(lief_errors::read_error);
  }


  tag = stream.asn1_read_tag(/* SpcPeImageData ::= SEQUENCE */
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  if (!tag) {
    LIEF_INFO("Wrong tag: 0x{:x} (pos: {:d})", stream_get_tag(stream), stream.pos());
    return tag.error();
  }


  /* SpcPeImageData */ {
    const size_t length = tag.value();
    std::vector<uint8_t> raw = {stream.p(), stream.p() + length};
    VectorStream spc_data_stream{std::move(raw)};
    stream.increment_pos(spc_data_stream.size());

    auto spc_data = parse_spc_pe_image_data(spc_data_stream);
    if (!spc_data) {
      LIEF_INFO("Can't parse SpcPeImageData");
    } else {
      const SpcPeImageData& spc_data_value = spc_data.value();
      content_info.file_  = spc_data_value.file;
      content_info.flags_ = spc_data_value.flags;
    }
  }

  // ================================================
  // DigestInfo ::= SEQUENCE
  // ================================================
  tag = stream.asn1_read_tag(/* DigestInfo */
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  if (!tag) {
    LIEF_INFO("Wrong tag 0x{:x} for DigestInfo ::= SEQUENCE (pos: {:d})",
              stream_get_tag(stream), stream.pos());
    return tag.error();
  }

  auto alg_identifier = stream.asn1_read_alg();
  if (!alg_identifier) {
    LIEF_INFO("Can't parse SignedData.contentInfo.messageDigest.digestAlgorithm (pos: {:d})",
              stream.pos());
    return alg_identifier.error();
  }

  LIEF_DEBUG("spc-indirect-data-content.digest-algorithm {}", oid_to_string(alg_identifier.value()));
  ALGORITHMS algo = algo_from_oid(alg_identifier.value());
  if (algo == ALGORITHMS::UNKNOWN) {
    LIEF_WARN("LIEF does not handle {}", alg_identifier.value());
  } else {
    content_info.digest_algorithm_ = algo;
  }

  // From the documentation:
  //  The value must match the digestAlgorithm value specified
  //  in SignerInfo and the parent PKCS #7 digestAlgorithms fields.
  auto digest = stream.asn1_read_octet_string();
  if (!digest) {
    LIEF_INFO("Can't parse SignedData.contentInfo.messageDigest.digest (pos: {:d})",
              stream.pos());
    return digest.error();
  }
  content_info.digest_ = std::move(digest.value());
  LIEF_DEBUG("spc-indirect-data-content.digest:  {}", hex_dump(content_info.digest_));
  return content_info;
}

result<SignatureParser::x509_certificates_t> SignatureParser::parse_certificates(VectorStream& stream) {
  x509_certificates_t certificates;
  const uint64_t cert_end_p = stream.size();
  while (stream.pos() < cert_end_p) {
    auto cert = stream.asn1_read_cert();
    if (!cert) {
      LIEF_INFO("Can't parse X509 cert pkcs7-signed-data.certificates (pos: {:d})", stream.pos());
      return cert.error();
      //break;
    }
    std::unique_ptr<mbedtls_x509_crt> cert_p = std::move(cert.value());

    if /* constexpr */(lief_logging_debug) {
      std::array<char, 1024> buffer = {0};
      mbedtls_x509_crt_info(buffer.data(), buffer.size(), "", cert_p.get());
      LIEF_DEBUG("\n{}\n", buffer.data());
    }
    certificates.emplace_back(cert_p.release());
  }
  return certificates;
}


result<SignatureParser::signer_infos_t> SignatureParser::parse_signer_infos(VectorStream& stream) {
  const uintptr_t end_set = stream.size();

  signer_infos_t infos;

  while (stream.pos() < end_set) {
    SignerInfo signer;
    const size_t current_p = stream.pos();

    auto tag = stream.asn1_read_tag(/* SignerInfo */
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (!tag) {
      LIEF_INFO("Wrong tag: 0x{:x} for pkcs7-signed-data.signer-infos SEQUENCE (pos: {:d})",
                stream_get_tag(stream), stream.pos());
      break;
    }

    // =======================================================
    // version Version
    // =======================================================
    auto version = stream.asn1_read_int();
    if (!version) {
      LIEF_INFO("Can't parse pkcs7-signed-data.signer-info.version (pos: {:d})", stream.pos());
      break;
    }

    int32_t version_val = version.value();
    LIEF_DEBUG("pkcs7-signed-data.signer-info.version: {}", version_val);
    if (version_val != 1) {
      LIEF_DEBUG("pkcs7-signed-data.signer-info.version: Bad version ({:d})", version_val);
      break;
    }
    signer.version_ = version_val;

    // =======================================================
    // IssuerAndSerialNumber ::= SEQUENCE {
    //   issuer       Name,
    //   serialNumber CertificateSerialNumber
    // }
    //
    // For Name see: https://github.com/ARMmbed/mbedtls/blob/9e4d4387f07326fff227a40f76c25e5181b1b1e2/library/x509_crt.c#L1180
    // =======================================================
    tag = stream.asn1_read_tag(/* Name */
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (!tag) {
      LIEF_INFO("Wrong tag: 0x{:x} for "
                "pkcs7-signed-data.signer-infos.issuer-and-serial-number.issuer (pos: {:d})",
                stream_get_tag(stream), stream.pos());
      break;
    }

    auto issuer = stream.x509_read_names();
    if (!issuer) {
      LIEF_INFO("Can't parse pkcs7-signed-data.signer-infos.issuer-and-serial-number.issuer (pos: {:d})",
                stream.pos());
      break;
    }

    LIEF_DEBUG("pkcs7-signed-data.signer-infos.issuer-and-serial-number.issuer: {} (pos: {:d})",
               issuer.value(), stream.pos());
    signer.issuer_ = std::move(issuer.value());

    auto sn = stream.x509_read_serial();
    if (!sn) {
      LIEF_INFO("Can't parse pkcs7-signed-data.signer-infos.issuer-and-serial-number.serial-number (pos: {:d})",
                stream.pos());
      break;
    }

    LIEF_DEBUG("pkcs7-signed-data.signer-infos.issuer-and-serial-number.serial-number {}", hex_dump(sn.value()));
    signer.serialno_ = std::move(sn.value());

    // =======================================================
    // Digest Encryption Algorithm
    // =======================================================
    {
      auto digest_alg = stream.asn1_read_alg();

      if (!digest_alg) {
        LIEF_INFO("Can't parse pkcs7-signed-data.signer-infos.digest-algorithm (pos: {:d})", stream.pos());
        break;
      }
      LIEF_DEBUG("pkcs7-signed-data.signer-infos.digest-algorithm: {}", oid_to_string(digest_alg.value()));

      ALGORITHMS dg_algo = algo_from_oid(digest_alg.value());
      if (dg_algo == ALGORITHMS::UNKNOWN) {
        LIEF_WARN("LIEF does not handle algorithm {}", digest_alg.value());
      } else {
        signer.digest_algorithm_ = dg_algo;
      }
    }

    // =======================================================
    // Authenticated Attributes
    // =======================================================
    {
      const uint64_t auth_attr_start = stream.pos();
      tag = stream.asn1_read_tag(/* authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL */
                                 MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
      if (tag) {
        const uint64_t auth_attr_end = stream.pos() + tag.value();
        std::vector<uint8_t> raw_authenticated_attributes = {stream.p(), stream.p() + tag.value()};
        VectorStream auth_stream(std::move(raw_authenticated_attributes));
        stream.increment_pos(auth_stream.size());
        auto authenticated_attributes = parse_attributes(auth_stream);
        if (!authenticated_attributes) {
          LIEF_INFO("Fail to parse pkcs7-signed-data.signer-infos.authenticated-attributes");
        } else {
          signer.raw_auth_data_ = {stream.start() + auth_attr_start, stream.start() + auth_attr_end};
          signer.authenticated_attributes_ = std::move(authenticated_attributes.value());
        }
      }
    }

    // =======================================================
    // Digest Encryption Algorithm
    // =======================================================
    {
      auto digest_enc_alg = stream.asn1_read_alg();
      if (!digest_enc_alg) {
        LIEF_INFO("Can't parse pkcs7-signed-data.signer-infos.digest-encryption-algorithm (pos: {:d})",
                  stream.pos());
        return digest_enc_alg.error();
      }
      LIEF_DEBUG("pkcs7-signed-data.signer-infos.digest-encryption-algorithm: {}",
                 oid_to_string(digest_enc_alg.value()));

      ALGORITHMS dg_enc_algo = algo_from_oid(digest_enc_alg.value());
      if (dg_enc_algo == ALGORITHMS::UNKNOWN) {
        LIEF_WARN("LIEF does not handle algorithm {}", digest_enc_alg.value());
      } else {
        signer.digest_enc_algorithm_ = dg_enc_algo;
      }
    }

    // =======================================================
    // Encrypted Digest
    // =======================================================
    {
      auto enc_digest = stream.asn1_read_octet_string();
      if (!enc_digest) {
        LIEF_INFO("Can't parse pkcs7-signed-data.signer-infos.encrypted-digest (pos: {:d})", stream.pos());
        return enc_digest.error();
      }
      LIEF_DEBUG("pkcs7-signed-data.signer-infos.encrypted-digest: {}",
                 hex_dump(enc_digest.value()).substr(0, 10));
      signer.encrypted_digest_ = enc_digest.value();
    }

    // =======================================================
    // Unauthenticated Attributes
    // =======================================================
    {
      tag = stream.asn1_read_tag(/* unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL */
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1);
      if (tag) {
        std::vector<uint8_t> raw_unauthenticated_attributes = {stream.p(), stream.p() + tag.value()};
        VectorStream unauth_stream(std::move(raw_unauthenticated_attributes));
        stream.increment_pos(unauth_stream.size());
        auto unauthenticated_attributes = parse_attributes(unauth_stream);
        if (!unauthenticated_attributes) {
          LIEF_INFO("Fail to parse pkcs7-signed-data.signer-infos.unauthenticated-attributes");
        } else {
          signer.unauthenticated_attributes_ = std::move(unauthenticated_attributes.value());
        }
      }
    }
    infos.push_back(std::move(signer));

    if (stream.pos() <= current_p) {
      break;
    }
  }
  return infos;
}


result<SignatureParser::attributes_t> SignatureParser::parse_attributes(VectorStream& stream) {
  // Attributes ::= SET OF Attribute
  //
  // Attribute ::= SEQUENCE
  // {
  //    type       EncodedObjectID,
  //    values     AttributeSetValue
  // }
  attributes_t attributes;
  const uint64_t end_pos = stream.size();
  while (stream.pos() < end_pos) {
    auto tag = stream.asn1_read_tag(/* Attribute ::= SEQUENCE */
                                    MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (!tag) {
      LIEF_INFO("Can't parse attribute (pos: {:d})", stream.pos());
      break;
    }

    auto oid = stream.asn1_read_oid();
    if (!oid) {
      LIEF_INFO("Can't parse attribute.type (pos: {:d})", stream.pos());
      break;
    }
    tag = stream.asn1_read_tag(/* AttributeSetValue */
                               MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED);
    if (!tag) {
      LIEF_DEBUG("attribute.values: Unable to get set for {}", oid.value());
      break;
    }
    const size_t value_set_size = tag.value();
    LIEF_DEBUG("attribute.values: {} ({:d} bytes)", oid_to_string(oid.value()), value_set_size);

    std::vector<uint8_t> raw = {stream.p(), stream.p() + value_set_size};
    VectorStream value_stream(std::move(raw));

    while (value_stream.pos() < value_stream.size()) {
      const uint64_t current_p = value_stream.pos();
      const std::string& oid_str = oid.value();

      if (oid_str == /* contentType */ "1.2.840.113549.1.9.3") {
        auto res = parse_content_type(value_stream);
        if (!res || res.value() == nullptr) {
          LIEF_INFO("Can't parse content-type attribute");
        } else {
          attributes.push_back(std::move(res.value()));
        }
      }

      else if (oid_str == /* SpcSpOpusInfo */ "1.3.6.1.4.1.311.2.1.12") {
        auto res = parse_spc_sp_opus_info(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse spc-sp-opus-info attribute");
        } else {
          SpcSpOpusInfo info = std::move(res.value());
          attributes.push_back(std::make_unique<PE::SpcSpOpusInfo>(std::move(info.program_name),
                                                                   std::move(info.more_info)));
        }
      }
      // TODO(romain): Parse the internal DER of Ms-CounterSign
      // else if (oid_str == /* Ms-CounterSign */ "1.3.6.1.4.1.311.3.3.1") {
      //   auto res = parse_ms_counter_sign(value_stream);
      //   if (not res) {
      //     LIEF_INFO("Can't parse ms-counter-sign attribute");
      //   }
      // }

      else if (oid_str == /* pkcs9-CounterSignature */ "1.2.840.113549.1.9.6") {
        auto res = parse_pkcs9_counter_sign(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse pkcs9-counter-sign attribute");
        } else {
          const std::vector<SignerInfo>& signers = res.value();
          if (signers.empty()) {
            LIEF_INFO("Can't parse signer info associated with the pkcs9-counter-sign");
          } else if (signers.size() > 1) {
            LIEF_INFO("More than one signer info associated with the pkcs9-counter-sign");
          } else {
            attributes.push_back(std::make_unique<PKCS9CounterSignature>(signers.back()));
          }
        }
      }

      else if (oid_str == /* Ms-SpcNestedSignature */ "1.3.6.1.4.1.311.2.4.1") {
        auto res = parse_ms_spc_nested_signature(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse ms-spc-nested-signature attribute");
        } else {
          attributes.push_back(std::make_unique<MsSpcNestedSignature>(std::move(res.value())));
        }
      }

      else if (oid_str == /* pkcs9-MessageDigest */ "1.2.840.113549.1.9.4") {
        auto res = parse_pkcs9_message_digest(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse pkcs9-message-digest attribute");
        } else {
          attributes.push_back(std::make_unique<PKCS9MessageDigest>(std::move(res.value())));
        }
      }

      else if (oid_str == /* Ms-SpcStatementType */ "1.3.6.1.4.1.311.2.1.11") {
        auto res = parse_ms_spc_statement_type(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse ms-spc-statement-type attribute");
        } else {
          attributes.push_back(std::make_unique<MsSpcStatementType>(std::move(res.value())));
        }
      }

      else if (oid_str == /* pkcs9-at-SequenceNumber */ "1.2.840.113549.1.9.25.4") {
        auto res = parse_pkcs9_at_sequence_number(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse ms-spc-statement-type attribute");
        } else {
          attributes.push_back(std::make_unique<PKCS9AtSequenceNumber>(*res));
        }
      }

      else if (oid_str == /* pkcs9-signing-time */ "1.2.840.113549.1.9.5") {
        auto res = parse_pkcs9_signing_time(value_stream);
        if (!res) {
          LIEF_INFO("Can't parse ms-spc-statement-type attribute");
        } else {
          attributes.push_back(std::make_unique<PKCS9SigningTime>(*res));
        }
      }

      else {
        LIEF_INFO("Unknown OID: {}", oid_str);
        attributes.push_back(std::make_unique<GenericType>(oid_str, value_stream.content()));
        break;
      }

      if (current_p >= value_stream.pos()) {
        LIEF_INFO("End-loop detected!");
        break;
      }
    }
    stream.increment_pos(value_set_size);
  }
  return attributes;
}

result<std::unique_ptr<Attribute>> SignatureParser::parse_content_type(VectorStream& stream) {
  /*
   *
   * ContentType ::= OBJECT IDENTIFIER
   * Content type as defined in https://tools.ietf.org/html/rfc2315#section-6.8
   */

  auto oid = stream.asn1_read_oid();
  if (!oid) {
    LIEF_INFO("Can't parse content-type.oid (pos: {:d})", stream.pos());
    return oid.error();
  }
  const std::string& oid_str = oid.value();
  LIEF_DEBUG("content-type.oid: {}", oid_to_string(oid_str));
  LIEF_DEBUG("content-type remaining bytes: {}", stream.size() - stream.pos());
  return std::unique_ptr<Attribute>{new ContentType{oid_str}};
}

result<SignatureParser::SpcSpOpusInfo> SignatureParser::parse_spc_sp_opus_info(VectorStream& stream) {
  // SpcSpOpusInfo ::= SEQUENCE {
  //   programName        [0] EXPLICIT SpcString OPTIONAL,
  //   moreInfo           [1] EXPLICIT SpcLink   OPTIONAL
  // }
  LIEF_DEBUG("Parse spc-sp-opus-info");
  SpcSpOpusInfo info;
  auto tag = stream.asn1_read_tag(/* SpcSpOpusInfo ::= SEQUENCE */
                                  MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
  if (!tag) {
    LIEF_INFO("Wrong tag for  spc-sp-opus-info SEQUENCE : 0x{:x} (pos: {:d})",
              stream_get_tag(stream), stream_->pos());
    return tag.error();
  }

  tag = stream.asn1_read_tag(/* programName [0] EXPLICIT SpcString OPTIONAL */
                              MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
  if (tag) {
    std::vector<uint8_t> raw = {stream.p(), stream.p() + tag.value()};
    VectorStream spc_string_stream(std::move(raw));
    auto program_name = parse_spc_string(spc_string_stream);
    if (!program_name) {
      LIEF_INFO("Fail to parse spc-sp-opus-info.program-name");
    } else {
      info.program_name = program_name.value();
    }
    stream.increment_pos(spc_string_stream.size());
  }
  tag = stream.asn1_read_tag(/* moreInfo [1] EXPLICIT SpcLink OPTIONAL */
                              MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1);
  if (tag) {
    std::vector<uint8_t> raw = {stream.p(), stream.p() + tag.value()};
    VectorStream spc_link_stream(std::move(raw));
    auto more_info = parse_spc_link(spc_link_stream);
    if (!more_info) {
      LIEF_INFO("Fail to parse spc-sp-opus-info.more-info");
    } else {
      info.more_info = more_info.value();
    }
    stream.increment_pos(spc_link_stream.size());
  }
  return info;
}

result<void> SignatureParser::parse_ms_counter_sign(VectorStream& stream) {
  LIEF_DEBUG("Parsing Ms-CounterSign ({} bytes)", stream.size());
  LIEF_DEBUG("TODO: Ms-CounterSign");
  stream.increment_pos(stream.size());
  return {};
}

result<SignatureParser::signer_infos_t> SignatureParser::parse_pkcs9_counter_sign(VectorStream& stream) {
  //
  // counterSignature ATTRIBUTE ::= {
  //          WITH SYNTAX SignerInfo
  //          ID pkcs-9-at-counterSignature
  //  }
  LIEF_DEBUG("Parsing pkcs9-CounterSign ({} bytes)", stream.size());
  auto counter_sig = parse_signer_infos(stream);
  if (!counter_sig) {
    LIEF_INFO("Fail to parse pkcs9-counter-signature");
    return counter_sig.error();
  }
  LIEF_DEBUG("pkcs9-counter-signature remaining bytes: {}", stream.size() - stream.pos());
  return counter_sig.value();
}

result<Signature> SignatureParser::parse_ms_spc_nested_signature(VectorStream& stream) {
  // SET of pkcs7-signed data
  LIEF_DEBUG("Parsing Ms-SpcNestedSignature ({} bytes)", stream.size());
  auto sign = SignatureParser::parse(stream.content(), /* skip header */ false);
  if (!sign) {
    LIEF_INFO("Ms-SpcNestedSignature finished with errors");
    return sign.error();
  }
  LIEF_DEBUG("ms-spc-nested-signature remaining bytes: {}", stream.size() - stream.pos());
  return sign.value();
}

result<std::vector<uint8_t>> SignatureParser::parse_pkcs9_message_digest(VectorStream& stream) {
  auto digest = stream.asn1_read_octet_string();
  if (!digest) {
    LIEF_INFO("Can't process OCTET STREAM for attribute.pkcs9-message-digest (pos: {})",
              stream.pos());
    return digest.error();
  }
  const std::vector<uint8_t>& raw_digest = digest.value();
  LIEF_DEBUG("attribute.pkcs9-message-digest {}", hex_dump(raw_digest));
  LIEF_DEBUG("pkcs9-message-digest remaining bytes: {}", stream.size() - stream.pos());
  return raw_digest;
}

result<oid_t> SignatureParser::parse_ms_spc_statement_type(VectorStream& stream) {
  // SpcStatementType ::= SEQUENCE of OBJECT IDENTIFIER
  LIEF_DEBUG("Parsing Ms-SpcStatementType ({} bytes)", stream.size());
  auto tag = stream.asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (!tag) {
    LIEF_INFO("Wrong tag for ms-spc-statement-type: 0x{:x} (pos: {:d})",
              stream_get_tag(stream), stream_->pos());
    return tag.error();
  }

  auto oid = stream.asn1_read_oid();
  if (!oid) {
    LIEF_INFO("Can't parse ms-spc-statement-type.oid (pos: {:d})", stream.pos());
    return oid.error();
  }
  const oid_t& oid_str = oid.value();
  LIEF_DEBUG("ms-spc-statement-type.oid: {}", oid_to_string(oid_str));
  LIEF_DEBUG("ms-spc-statement-type remaining bytes: {}", stream.size() - stream.pos());
  return oid_str;
}

result<int32_t> SignatureParser::parse_pkcs9_at_sequence_number(VectorStream& stream) {
  LIEF_DEBUG("Parsing pkcs9-at-SequenceNumber ({} bytes)", stream.size());
  auto value = stream.asn1_read_int();
  if (!value) {
    LIEF_INFO("pkcs9-at-sequence-number: Can't parse integer");
    return value.error();
  }
  LIEF_DEBUG("pkcs9-at-sequence-number.int: {}", value.value());
  LIEF_DEBUG("pkcs9-at-sequence-number remaining bytes: {}", stream.size() - stream.pos());
  return value.value();
}

result<std::string> SignatureParser::parse_spc_string(VectorStream& stream) {
  // SpcString ::= CHOICE {
  //     unicode                 [0] IMPLICIT BMPSTRING,
  //     ascii                   [1] IMPLICIT IA5STRING
  // }
  LIEF_DEBUG("Parse SpcString ({} bytes)", stream.size());
  auto choice = stream.asn1_read_tag(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
  if (choice) {
    LIEF_DEBUG("SpcString: Unicode choice");
    const size_t length = choice.value();
    LIEF_DEBUG("spc-string.program-name length: {} (pos: {})", length, stream.pos());

    if (!stream.can_read<char16_t>(length / sizeof(char16_t))) {
      LIEF_INFO("Can't read spc-string.program-name");
      return make_error_code(lief_errors::read_error);
    }
    stream.set_endian_swap(true);

    auto progname = stream.read_u16string(length / sizeof(char16_t));
    if (!progname) {
      LIEF_INFO("Can't read spc-string.program-name");
      stream.set_endian_swap(false);
      return make_error_code(lief_errors::read_error);
    }

    stream.set_endian_swap(false);

    try {
      return u16tou8(*progname);
    } catch (const utf8::exception&) {
      LIEF_INFO("Error while converting utf-8 spc-string.program-name to utf16");
      return make_error_code(lief_errors::conversion_error);
    }
  }
  if ((choice = stream.asn1_read_tag(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1))) {
    LIEF_DEBUG("SpcString: ASCII choice");
    const size_t length = choice.value();
    const char* str = stream.read_array<char>(length);
    if (str == nullptr) {
      LIEF_INFO("Can't read spc-string.program-name");
      return make_error_code(lief_errors::read_error);
    }
    std::string u8progname{str, str + length};
    LIEF_DEBUG("spc-string.program-name: {}", u8progname);
    return u8progname;
  }

  LIEF_INFO("Can't select choice for SpcString (pos: {})", stream.pos());
  return make_error_code(lief_errors::read_error);
}

result<std::string> SignatureParser::parse_spc_link(VectorStream& stream) {
  // SpcLink ::= CHOICE {
  //     url                     [0] IMPLICIT IA5STRING,
  //     moniker                 [1] IMPLICIT SpcSerializedObject,
  //     file                    [2] EXPLICIT SpcString
  // }
  LIEF_DEBUG("Parse SpcLink ({} bytes)", stream.size());
  auto choice = stream.asn1_read_tag(/* url */ MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
  if (choice) {
    const size_t length = choice.value();
    const char* str = stream.read_array<char>(length);
    if (str == nullptr) {
      LIEF_INFO("Can't read spc-link.url");
      return make_error_code(lief_errors::read_error);
    }
    std::string url{str, str + length};
    LIEF_DEBUG("spc-link.url: {}", url);
    return url;
  }

  if ((choice = stream.asn1_read_tag(/* moniker */ MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1))) {
    LIEF_INFO("Parsing spc-link.moniker is not supported");
    return make_error_code(lief_errors::not_supported);
  }

  if ((choice = stream.asn1_read_tag(/* file */ MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2))) {
    LIEF_INFO("Parsing spc-link.file is not supported");
    return make_error_code(lief_errors::not_supported);
  }

  LIEF_INFO("Corrupted choice for spc-link (choice: 0x{:x})", stream_get_tag(stream));
  return make_error_code(lief_errors::corrupted);
}


result<SignatureParser::time_t> SignatureParser::parse_pkcs9_signing_time(VectorStream& stream) {
  // See: https://tools.ietf.org/html/rfc2985#page-20
  // UTCTIME           :171116220536Z
  auto tm = stream.x509_read_time();
  if (!tm) {
    LIEF_INFO("Can't read pkcs9-signing-time (pos: {})", stream.pos());
    return tm.error();
  }
  std::unique_ptr<mbedtls_x509_time> time = std::move(tm.value());
  LIEF_DEBUG("pkcs9-signing-time {}/{}/{}", time->day, time->mon, time->year);
  return SignatureParser::time_t{time->year, time->mon, time->day,
                                 time->hour, time->min, time->sec};
}


result<SignatureParser::SpcPeImageData> SignatureParser::parse_spc_pe_image_data(VectorStream&) {
  // SpcPeImageData ::= SEQUENCE {
  //   flags SpcPeImageFlags DEFAULT { includeResources },
  //   file  SpcLink
  // }
  //
  // SpcPeImageFlags ::= BIT STRING {
  //   includeResources          (0),
  //   includeDebugInfo          (1),
  //   includeImportAddressTable (2)
  // }
  //
  // SpcLink ::= CHOICE {
  //   url     [0] IMPLICIT IA5STRING,
  //   moniker [1] IMPLICIT SpcSerializedObject,
  //   file    [2] EXPLICIT SpcString
  // }
  //
  // SpcString ::= CHOICE {
  //   unicode [0] IMPLICIT BMPSTRING,
  //   ascii   [1] IMPLICIT IA5STRING
  // }
  //LIEF_DEBUG("Parse SpcPeImageData ({} bytes)", stream.size());
  //auto tag = stream.asn1_read_tag(MBEDTLS_ASN1_BIT_STRING);
  //if (not tag) {
  //  LIEF_INFO("Wrong tag for spc-pe-image-data.flags \
  //      Expecting BIT-STRING but got 0x{:x} (off: {:d})", stream.peek<uint8_t>(), stream.pos());
  //  return tag.error();
  //}
  //LIEF_DEBUG("Length: {}", tag.value());
  //uint8_t flag = stream.read<uint8_t>();
  //LIEF_DEBUG("flag: {:b}", flag);

  //tag = stream.asn1_read_tag(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
  //if (not tag) {
  //  LIEF_INFO("Wrong tag for spc-pe-image-data.flags \
  //      Expecting BIT-STRING but got 0x{:x} (off: {:d})", stream.peek<uint8_t>(), stream.pos());
  //  return tag.error();
  //}
  ////LIEF_INFO("spc-pe-image-data.flags length: {:d}", flags.value().size());
  //auto file = parse_spc_link(stream);
  //if (not file) {
  //  LIEF_INFO("Can't parse spc-pe-image-data.file (pos: {})", stream.pos());
  //  return file.error();
  //}

  return {};
}


}
}


