/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
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

#include <mbedtls/x509_crt.h>

#include "utf8.h"
#include "LIEF/utils.hpp"

#include "LIEF/logging++.hpp"

#include <cstring>
#include <memory>

#include "LIEF/exception.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Structures.hpp"

#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/SignatureUtils.hpp"
#include "LIEF/PE/signature/SpcIndirectDataContent.hpp"

#include "LIEF/PE/signature/OIDDefinitions.h"

using mapbox::util::get;

// ref: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx

namespace LIEF {
namespace PE {

SignatureParser::~SignatureParser(void) = default;
SignatureParser::SignatureParser(void) = default;

SignatureParser::SignatureParser(const std::vector<uint8_t>& data) :
  signatures_{},
  p_{nullptr},
  end_{nullptr},
  signature_ptr_{nullptr},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})}
{
  try {
    this->parse_signatures();
  } catch (const std::exception& e) {
    VLOG(VDEBUG) << e.what();
  }
}


std::vector<Signature> SignatureParser::parse(const std::vector<uint8_t>& data) {
  SignatureParser parser{data};
  return std::move(parser.signatures_);
}

size_t SignatureParser::current_offset(void) const {
  return (reinterpret_cast<size_t>(this->p_) - reinterpret_cast<size_t>(this->signature_ptr_));
}


void SignatureParser::parse_content_type(Signature& signature) {
  /*
   * ContentType ::= OBJECT IDENTIFIER
   */
  const auto oid_str = get_oid_numeric_str(this->p_, this->end_);
  if (oid_str != OID_PKCS7_SIGNED_DATA) {
    throw corrupted(std::string("Wrong OID: ") + oid_str + " (expect PKCS7_SIGNED_DATA)");
  }
  signature.content_type_ = oid_str;
}


int32_t SignatureParser::get_signed_data_version(void) {
  VLOG(VDEBUG) << "Parse signed data - version";

  int32_t version;
  if (mbedtls_asn1_get_int(&(this->p_), this->end_, &version) != 0) {
    throw corrupted("Signature corrupted");
  }

  VLOG(VDEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "Version should be equal to 1 (" << std::dec << version << ")";
  return version;
}


std::string SignatureParser::get_signed_data_digest_algorithms(void) {
  /*
   * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
   * NOTE: Because Authenticode signatures support only one signer, digestAlgorithms must
contain only one digestAlgorithmIdentifier structure
   */
  VLOG(VDEBUG) << "Parse signed data - digest algorithm";
  size_t len = 0;
  ASN1_GET_TAG(this->p_, end_, len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET, "Signature corrupted");
  auto alg_oid = get_algorithm_identifier_oid(this->p_, this->p_ + len);
  if (alg_oid.empty()) {
    throw corrupted("Signature corrupted");
  }
  VLOG(VDEBUG) << "digestAlgorithms: " << alg_oid;
  return alg_oid;
}


std::unique_ptr<SpcIndirectDataContent> SignatureParser::parse_spc_indirect_data_content(void) {
  /*
   * SpcIndirectDataContent ::= SEQUENCE {
   *   data SpcAttributeTypeAndOptionalValue,
   *   messageDigest DigestInfo
   * } --#public—
   */

  auto spc_indirect_data_content = std::make_unique<SpcIndirectDataContent>();

  /*
   * SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
   *   type ObjectID,
   *   value [0] EXPLICIT ANY OPTIONAL (MUST be SpcPeImageData)
   * }
   */
  VLOG(VDEBUG) << "Parsing SpcIndirectDataContent (offset: "
               << std::dec << this->current_offset()
               << ")";
  auto next_content_len
    = get_next_content_len(this->p_, this->end_,MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  // Save off raw now so that it covers everything else in the ContentInfo
  spc_indirect_data_content->raw_ = {this->p_, this->p_ + next_content_len};

  VLOG(VDEBUG) << "Parsing SpcAttributeTypeAndOptionalValue (offset: "
               << std::dec << this->current_offset()
               << ")";
  next_content_len = get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  auto oid_str = get_oid_numeric_str(this->p_, this->end_);
  if (oid_str != OID_SPC_PE_IMAGE_DATA_OBJ) {
    throw corrupted(oid_str + " is not SPC_PE_IMAGE_DATAOBJ");
  }
  VLOG(VDEBUG) << "SpcAttributeTypeAndOptionalValue->type " << oid_str << " (" << oid_to_string(oid_str) << ")";
  spc_indirect_data_content->type_ = oid_str;

  /*
   * SpcPeImageData ::= SEQUENCE {
   *   flags SpcPeImageFlags DEFAULT { includeResources },
   *   file SpcLink
   * } --#public--
   */
  VLOG(VDEBUG) << "Parsing SpcPeImageData (offset: "
               << std::dec << this->current_offset()
               << ")";
  next_content_len = get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  /*
   * SpcPeImageFlags ::= BIT STRING {
   *   includeResources (0),
   *   includeDebugInfo (1),
   *   includeImportAddressTable (2)
   * }
   */
  VLOG(VDEBUG) << "Parsing SpcPeImageFlags (offset: "
               << std::dec <<  this->current_offset()
               << ")";
  next_content_len = get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_BIT_STRING);
  spc_indirect_data_content->flags_ = static_cast<SPC_PE_IMAGE_FLAGS>(*this->p_);
  this->p_ += next_content_len;

  /*
   * SpcLink ::= CHOICE {
   *   url [0] IMPLICIT IA5STRING,
   *   moniker [1] IMPLICIT SpcSerializedObject,
   *   file [2] EXPLICIT SpcString // always set to file in this case
   * } --#public--
   * SpcString ::= CHOICE {
   *   unicode [0] IMPLICIT BMPSTRING,
   *   ascii [1] IMPLICIT IA5STRING
   * }
   */
  VLOG(VDEBUG) << "Parsing SpcLink";
  next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
  const auto spc_link = get_spc_link(this->p_, this->end_);
  if (spc_link.first == "file") {
    spc_indirect_data_content->file_ = get<std::string>(spc_link.second);
  }

  /*
   * DigestInfo ::= SEQUENCE {
   *   digestAlgorithm AlgorithmIdentifier,
   *   digest OCTETSTRING
   * }
   * AlgorithmIdentifier ::= SEQUENCE {
   *   algorithm ObjectID,
   *   parameters [0] EXPLICIT ANY OPTIONAL
   * }
   */
  // digestAlgorithm
  next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  oid_str = get_algorithm_identifier_oid(this->p_, this->end_);
  if (oid_str.empty()) {
    throw corrupted("Signature corrupted");
  }
  VLOG(VDEBUG) << "DigestInfo->digestAlgorithm: " << oid_str << " (" << oid_to_string(oid_str) << ")";
  spc_indirect_data_content->digest_algorithm_ = oid_str;

  // digest
  next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_OCTET_STRING);
  spc_indirect_data_content->digest_ = {this->p_, this->p_ + next_content_len};
  this->p_ += next_content_len;

  return spc_indirect_data_content;
}


std::unique_ptr<ContentInfo> SignatureParser::parse_content_info(void) {
  VLOG(VDEBUG) << "Parse signed data - content info";

  /*
   * ContentInfo ::= SEQUENCE {
   *   content-type   PKCS7-CONTENT-TYPE.&id({PKCS7ContentTable}),
   *   content
   *     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
   * }
   */
  auto next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  const auto content_type = get_oid_numeric_str(this->p_, this->end_);
  next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);

  if (content_type == OID_SPC_INDIRECT_DATA_OBJ) {
    auto content_info = parse_spc_indirect_data_content();
    content_info->content_type_ = content_type;
    return content_info;
  } else if (content_type == OID_T_ST_INFO) {
    // TODO:
    VLOG(VDEBUG) << "Currently TSTInfo is not supported";
  }

  return nullptr;
}


void SignatureParser::parse_certificates(Signature& signature) {
  /*
   * CertificateSet ::= SET OF CertificateChoice
   * CertificateChoice ::= CHOICE {
   *   certificate           Certificate,
   *   extendedCertificate   [0]  ExtendedCertificate, -- Obsolete
   *   attributeCertificate  [1]  AttributeCertificate
   * }
   */
  VLOG(VDEBUG) << "Parsing Certificates (offset: "
             << std::dec << this->current_offset()
             << ")";

  const auto next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);

  uint8_t* cert_end = this->p_ + next_content_len;
  while (this->p_ < cert_end) {
    auto ca = get_x509_crt(this->p_, this->end_) ;
    if (!ca) break;

    signature.certificates_.emplace_back(ca.get());
    this->p_ += ca->raw.len;
    ca.release();
  }

  // If one of the certificates failed to parse for some reason, skip past
  // the certificate section so that we have a chance of parsing the rest
  // of the signature.
  if (this->p_ < cert_end) {
    this->p_ = cert_end;
  }
}

AuthenticatedAttributes SignatureParser::get_authenticated_attributes(void) {
  VLOG(VDEBUG) << "Parsing authenticatedAttributes (offset: "
             << std::dec << this->current_offset()
             << ")";

  AuthenticatedAttributes authenticated_attributes;

  uint8_t *p_start = this->p_;
  if (*p_start != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) {
    throw corrupted("Authenticated attributes is not found");
  }

  auto next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);

  authenticated_attributes.raw_ = {p_start, p_start + (this->p_ - p_start) + next_content_len};

  uint8_t* p_end = this->p_ + next_content_len;
  while(this->p_ < p_end) {
    next_content_len =
            get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

    const auto oid_str = get_oid_numeric_str(this->p_, this->end_);

    next_content_len =
            get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED);
    VLOG(VDEBUG) << "Parsing contentType (offset: "
                 << std::dec << this->current_offset()
                 << ")";
    VLOG(VDEBUG) << oid_str << " (" << oid_to_string(oid_str) << ")";
    if (oid_str == OID_CONTENT_TYPE) {
      // contentType
      // |_ OID (PKCS #9 Message Digest)
      // |_ SET -> OID
      // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      const auto oid_str = get_oid_numeric_str(this->p_, this->end_);
      authenticated_attributes.content_type_ = oid_str;
      continue;
    } else if (oid_str == OID_MESSAGE_DIGEST) {
      // messageDigest (Octet string)
      // |_ OID (PKCS #9 Message Digest)
      // |_ SET -> OCTET STING
      // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      size_t len = 0;
      ASN1_GET_TAG(this->p_, this->end_, len, MBEDTLS_ASN1_OCTET_STRING, "Signature corrupted: Can't read 'ASN1_OCTET_STRING'");
      authenticated_attributes.message_digest_ = {this->p_, this->p_ + len};
      this->p_ += len;
      continue;
    } else if (oid_str == OID_SPC_SP_OPUS_INFO_OBJ) {
      size_t len = 0;
      /*
       * SpcSpOpusInfo ::= SEQUENCE {
       *   programName [0] EXPLICIT SpcString OPTIONAL,
       *   moreInfo [1] EXPLICIT SpcLink OPTIONAL,
       * } --#public--
       */
      next_content_len =
              get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
      if (next_content_len == 0) {
        VLOG(VDEBUG) << "No program name or more info specified ";
        authenticated_attributes.program_name_ = u"";
        authenticated_attributes.more_info_ = {"", ""};
        continue;
      }

      uint8_t* seq_end = this->p_ + next_content_len;

      if (*this->p_ == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) {
        this->p_ += 1;
        if (mbedtls_asn1_get_len(&(this->p_), this->end_, &len) != 0) {
          VLOG(VDEBUG) << "Unexpected format for SpcSpOpusInfo [0] block ";
          throw corrupted("Authenticated attributes corrupted");
        }

        const auto progname = get_spc_string(this->p_, this->end_);
        VLOG(VDEBUG) << "ProgName " << progname;
        authenticated_attributes.program_name_ = u8tou16(progname);

        if (this->p_ >= seq_end) {
          VLOG(VDEBUG) << "No more info specified ";
          authenticated_attributes.more_info_ = {"", ""};
          continue;
        }

      } else {
        VLOG(VDEBUG) << "No program name specified ";
        authenticated_attributes.program_name_ = u"";
      }

      // moreInfo
      // ++++++++
      if (*this->p_ == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1)) {
        this->p_ += 1;
        if (mbedtls_asn1_get_len(&(this->p_), this->end_, &len) != 0) {
          VLOG(VDEBUG) << "Unexpected format for SpcSpOpusInfo [1] block ";
          throw corrupted("Authenticated attributes corrupted");
        }
        VLOG(VDEBUG) << "Parsing moreInfo";
        const auto spc_link = get_spc_link(this->p_, this->end_);
        if (spc_link.first == "url") {
          authenticated_attributes.more_info_ = get<std::string>(spc_link.second);
          VLOG(VDEBUG) << authenticated_attributes.more_info_;
        } else {
          VLOG(VDEBUG) << "moreInfo should contain a URL for a Web site with more information about the signer. ";
        }
      }
    } else {
      VLOG(VDEBUG) << "Skipping OID " << oid_str;
      this->p_ += next_content_len;
      continue;
    }
  }

  return authenticated_attributes;
}

Signature SignatureParser::get_nested_signature(void) {
  Signature nested_signature;
  const auto cur_top = this->p_;

  const auto next_content_len
    = get_next_content_len(this->p_, end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  const auto header_length = static_cast<uint32_t>(this->p_ - cur_top);
  nested_signature.length_ = next_content_len + header_length;
  nested_signature.original_raw_signature_ = {cur_top, cur_top + nested_signature.length_};

  // NOTE: assuming certificate revision and certificate type
  nested_signature.revision_ = CERTIFICATE_REVISION::WIN_CERT_REVISION_2_0;
  nested_signature.certificate_type_ = CERTIFICATE_TYPE::WIN_CERT_TYPE_PKCS_SIGNED_DATA;

  parse_content_type(nested_signature);
  parse_signed_data(nested_signature);
  return nested_signature;
}

UnauthenticatedAttributes SignatureParser::get_unauthenticated_attributes(void) {
  VLOG(VDEBUG) << "Parsing unauthenticatedAttributes (offset: "
              << std::dec << this->current_offset()
              << ")";

  UnauthenticatedAttributes unauthenticated_attributes;

  if (*this->p_ != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1)) {
    throw corrupted("Unauthenticated attributes is not found");
  }

  auto next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1);

  uint8_t* p_end = this->p_ + next_content_len;
  while (this->p_ < p_end) {
    next_content_len =
            get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

    const auto oid_str = get_oid_numeric_str(this->p_, this->end_);
    unauthenticated_attributes.content_type_ = oid_str;

    ASN1_GET_TAG(this->p_, this->end_, next_content_len,
                 MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED,
                 "Unauthenticated attributes corrupted");

    const auto restart_p = this->p_ + next_content_len;
    try {
      if (oid_str == OID_COUNTER_SIGNATURE) {
        VLOG(VDEBUG) << "Parsing countersignature (offset: " << std::dec << this->current_offset() << ")";
        unauthenticated_attributes.counter_signature_ = std::make_unique<SignerInfo>(get_signer_info());
        continue;
      } else if (oid_str == OID_MS_SPC_NESTED_SIGNATURE) {
        VLOG(VDEBUG) << "Parsing nested signature (offset: " << std::dec << this->current_offset() << ")";
        unauthenticated_attributes.nested_signature_ = std::make_unique<Signature>(get_nested_signature());
        continue;
      } else if (oid_str == OID_MS_COUNTER_SIGN) {
        VLOG(VDEBUG) << "Parsing Timestamp signature (offset: " << std::dec << this->current_offset() << ")";
        VLOG(VDEBUG) << "Currently not supported";

#if 0
        TODO:
        Signature timestamp_signature;
        get_next_content_len(this->p_, end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        this->parse_content_type();
        this->parse_signed_data(timestamp_signature);
#else
        this->p_ += next_content_len; // for debug purpose
#endif

        continue;
      } else {
        VLOG(VDEBUG) << "Unsupported OID " << oid_str;
        this->p_ = restart_p;
        continue;
      }
    } catch (corrupted& err) {
      VLOG(VDEBUG) << err.what();
      this->p_ = restart_p;
    }
  }

  return unauthenticated_attributes;
}

SignerInfo SignatureParser::get_signer_infos(void) {
  /*
   * SignerInfos ::= SET OF SignerInfo
   */
  // Because Authenticode supports only one signer,
  // only one SignerInfo structure is in signerInfos.
  get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED);
  return get_signer_info();
}

SignerInfo SignatureParser::get_signer_info(void) {
  /*
   * SignerInfo ::= SEQUENCE {
   *   version Version,
   *   issuerAndSerialNumber IssuerAndSerialNumber,
   *   digestAlgorithm DigestAlgorithmIdentifier,
   *   authenticatedAttributes
   *     [0] IMPLICIT Attributes OPTIONAL,
   *   digestEncryptionAlgorithm
   *     DigestEncryptionAlgorithmIdentifier,
   *   encryptedDigest EncryptedDigest,
   *   unauthenticatedAttributes
   *     [1] IMPLICIT Attributes OPTIONAL
   * }
   * EncryptedDigest ::= OCTET STRING
   */
  SignerInfo signer_info;
  auto next_content_len =
          get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

  // Version ::= INTEGER
  int32_t version = 0;
  if (mbedtls_asn1_get_int(&(this->p_), this->end_, &version) != 0) {
    throw corrupted("Signer info corrupted");
  }
  VLOG(VDEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "SignerInfo's version should be equal to 1 (" << std::dec << version << ")";
  signer_info.version_ = version;

  /*
   * IssuerAndSerialNumber ::= SEQUENCE {
   *   issuer Name,
   *   serialNumber CertificateSerialNumber
   * }
   */
  VLOG(VDEBUG) << "Parsing issuerAndSerialNumber (offset: "
             << std::dec << this->current_offset()
             << ")";
  next_content_len = get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

  // Name
  // ~~~~
  next_content_len = get_next_content_len(this->p_, this->end_, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
  const auto issuer_name = get_issuer_name(this->p_, this->p_ + next_content_len);
  if (issuer_name.empty()) {
    throw corrupted("Signer info corrupted");
  }
  VLOG(VDEBUG) << "Issuer: " << issuer_name;

  // CertificateSerialNumber (issuer SN)
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mbedtls_x509_buf serial;
  if (mbedtls_x509_get_serial(&(this->p_), this->end_, &serial) != 0) {
      throw corrupted("Signer info corrupted");
  }
  std::vector<uint8_t> certificate_sn = {serial.p, serial.p + serial.len};
  signer_info.issuer_ = {issuer_name, certificate_sn};

  // digestAlgorithm
  // ---------------
  VLOG(VDEBUG) << "Parsing digestAlgorithm (offset: "
               << std::dec << this->current_offset()
               << ")";
  auto oid_str = get_algorithm_identifier_oid(this->p_, this->end_);
  if (oid_str.empty()) {
    throw corrupted("Signer info corrupted");
  }
  VLOG(VDEBUG) << "signerInfo->digestAlgorithm " << oid_str << " (" << oid_to_string(oid_str) << ")";
  signer_info.digest_algorithm_ = oid_str;

  // authenticatedAttributes (IMPLICIT OPTIONAL)
  // |_ contentType
  // |_ messageDigest
  // |_ SpcSpOpusInfo
  // -----------------------
  try {
    signer_info.authenticated_attributes_ = this->get_authenticated_attributes();
    signer_info.has_authenticated_attributes_ = true;
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // digestEncryptionAlgorithm
  // -------------------------
  oid_str = get_algorithm_identifier_oid(this->p_, this->end_);
  if (oid_str.empty()) {
    throw corrupted("Signer info corrupted");
  }
  VLOG(VDEBUG) << "digestEncryptionAlgorithm: " << oid_str << " (" << oid_to_string(oid_str) << ")";
  signer_info.signature_algorithm_ = oid_str;

  // encryptedDigest
  // ---------------
  size_t len = 0;
  ASN1_GET_TAG(this->p_, this->end_, len, MBEDTLS_ASN1_OCTET_STRING, "Signer info corrupted");
  signer_info.encrypted_digest_ = {this->p_, this->p_ + len};
  this->p_ += len;

  // unauthenticatedAttributes
  // -------------------------
  try {
    signer_info.unauthenticated_attributes_ = this->get_unauthenticated_attributes();
    signer_info.has_unauthenticated_attributes_ = true;
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  return signer_info;

}

// See: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
void SignatureParser::parse_signatures(void) {
  const auto end_pos = this->stream_->size();
  while (this->stream_->pos() < end_pos) {
    Signature signature;

    const auto cur_top = this->stream_->pos();
    signature.length_ = this->stream_->read<uint32_t>();
    signature.revision_ = static_cast<CERTIFICATE_REVISION>(this->stream_->read<int16_t>());
    signature.certificate_type_ = static_cast<CERTIFICATE_TYPE>(this->stream_->read<int16_t>());
    const auto cur_end = cur_top + signature.length_;
    const auto content_len = cur_end - this->stream_->pos();

    VLOG(VDEBUG) << "Signature Size: 0x" << std::hex << signature.length();
    VLOG(VDEBUG) << "Signature Revision " << to_string(signature.revision());
    VLOG(VDEBUG) << "Signature Type " << to_string(signature.certificate_type());

    this->signature_ptr_
      = this->stream_->peek_array<uint8_t>(this->stream_->pos(), content_len, /* check */ false);
    this->end_ = this->signature_ptr_ + content_len;
    this->p_   = const_cast<uint8_t*>(this->signature_ptr_);

    signature.original_raw_signature_ = {this->signature_ptr_, this->end_};

    /*
     * ContentInfo ::= SEQUENCE {
     *   contentType ContentType,
     *   content
     *     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
     * }
     */
    const auto len = get_next_content_len(this->p_, end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    VLOG(VDEBUG) << "ContentInfo length is " << std::dec << len;
    this->parse_content_type(signature);
    this->parse_signed_data(signature);

    this->signatures_.emplace_back(std::move(signature));

    this->stream_->setpos(cur_end);
    this->stream_->align(8);
  }
}

void SignatureParser::parse_signed_data(Signature& signature) {
  /*
   * content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
   */
  auto next_content_len = get_next_content_len(this->p_, end_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);

  /*
   * SignedData ::= SEQUENCE {
   *   version Version,
   *   digestAlgorithms DigestAlgorithmIdentifiers,
   *   contentInfo ContentInfo,
   *   certificates
   *   [0] IMPLICIT ExtendedCertificatesAndCertificates
   *   OPTIONAL,
   *   Crls
   *   [1] IMPLICIT CertificateRevocationLists OPTIONAL,
   *   signerInfos SignerInfos
   * }
   */
  next_content_len = get_next_content_len(this->p_, this->p_ + next_content_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

  // version
  // =======
  signature.version_ = static_cast<uint32_t>(this->get_signed_data_version());

  // digestAlgorithms
  // =======================
  try {
    signature.digest_algorithm_ = this->get_signed_data_digest_algorithms();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // contentInfo
  // |_ contentType
  // |_ content (SpcIndirectDataContent)
  // ===================================
  try {
    signature.content_info_ = this->parse_content_info();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // Certificates
  // ============
  try {
    this->parse_certificates(signature);
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // signerInfo
  // ==========
  try {
    signature.signer_info_ = this->get_signer_infos();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }
}

}
}


