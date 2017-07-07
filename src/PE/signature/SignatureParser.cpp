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

#include <mbedtls/platform.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "LIEF/utf8.h"

#include "easylogging++.h"

#include "pkcs7.h"

#include "LIEF/exception.hpp"

#include "LIEF/PE/utils.hpp"

#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

namespace LIEF {
namespace PE {

SignatureParser::~SignatureParser(void) = default;
SignatureParser::SignatureParser(void) = default;

SignatureParser::SignatureParser(const std::vector<uint8_t>& data) :
  signature_{},
  p_{nullptr},
  end_{nullptr},
  signature_ptr_{nullptr},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})}
{

  this->signature_ptr_ = reinterpret_cast<const uint8_t*>(this->stream_->read(8, this->stream_->size() - 8));
  this->end_ = this->signature_ptr_ + this->stream_->size() - 8;
  this->p_ = const_cast<uint8_t*>(this->signature_ptr_);

  this->parse_signature();
}


Signature SignatureParser::parse(const std::vector<uint8_t>& data) {
  SignatureParser parser{data};
  return parser.signature_;
}

size_t SignatureParser::current_offset(void) const {
  return (reinterpret_cast<size_t>(this->p_) - reinterpret_cast<size_t>(this->signature_ptr_));
}


void SignatureParser::parse_header(void) {
  mbedtls_asn1_buf buf;
  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  buf.tag = *this->p_;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &buf.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Error while reading tag");
  }

  buf.p = this->p_;
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &buf);
  LOG(DEBUG) << "OID (signedData): " << oid_str;
  this->p_ += buf.len;

  if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_SIGNED_DATA, &buf) != 0) {
    throw corrupted("Wrong OID: " + std::string(oid_str) + " (expect PKCS7_SIGNED_DATA)");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

}


int32_t SignatureParser::get_signed_data_version(void) {
  LOG(DEBUG) << "Parse signed data - version";
  int ret = 0;

  int32_t version;
  if ((ret = mbedtls_asn1_get_int(&(this->p_), this->end_, &version)) != 0) {
    throw corrupted("Signature corrupted");
  }

  LOG(DEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "Version should be equal to 1 (" << std::dec << version << ")";
  return version;
}


std::string SignatureParser::get_signed_data_digest_algorithms(void) {
  LOG(DEBUG) << "Parse signed data - digest algorithm";
  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
    throw corrupted("Signature corrupted");
  }

  mbedtls_asn1_buf alg_oid;

  if ((ret = mbedtls_asn1_get_alg_null(&(this->p_), this->end_, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }

  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);

  LOG(DEBUG) << "digestAlgorithms: " << oid_str;
  return oid_str;

}


ContentInfo SignatureParser::parse_content_info(void) {
  LOG(DEBUG) << "Parse signed data - content info";

  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };
  mbedtls_asn1_buf alg_oid;
  mbedtls_asn1_buf content_type_oid;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  ContentInfo content_info;
  content_info.content_type_ = this->get_content_info_type();

  // content - SpcIndirectDataContent
  // |_ SpcAttributeTypeAndOptionalValue
  // |_ DigestInfo
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LOG(DEBUG) << "Parsing SpcIndirectDataContent (offset: "
             << std::dec << this->current_offset()
             << ")";

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  this->p_ += tag; // skip
  return content_info;
#if 0
  // SpcAttributeTypeAndOptionalValue
  // |_ SPC_PE_IMAGE_DATAOBJ
  // |_ SpcPeImageData
  // ++++++++++++++++++++++++++++++++
  LOG(DEBUG) << "Parsing SpcAttributeTypeAndOptionalValue (offset: "
             << std::dec << this->current_offset()
             << ")";
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *this->p_;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_type_oid.p = this->p_;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  LOG(DEBUG) << "SpcAttributeTypeAndOptionalValue->type " << oid_str;

  content_info.type_ = oid_str;
  this->p_ += content_type_oid.len;

  // SpcPeImageData
  // |_ SpcPeImageFlags
  // |_ SpcLink
  // ++++++++++++++
  LOG(DEBUG) << "Parsing SpcPeImageData (offset: "
             << std::dec << this->current_offset()
             << ")";

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // SpcPeImageFlags
  // ^^^^^^^^^^^^^^^
  LOG(DEBUG) << "Parsing SpcPeImageFlags (offset: "
             << std::dec <<  this->current_offset()
             << ")";
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_BIT_STRING)) != 0) {
    throw corrupted("Signature corrupted");
  }
  this->p_ += tag; // skip

  // SpcLink
  // ^^^^^^^
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }
  this->p_ += tag; // skip

  // DigestInfo
  // ++++++++++
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_alg_null(&(this->p_), this->end_, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  LOG(DEBUG) << "DigestInfo->digestAlgorithm: " << oid_str;

  content_info.digest_algorithm_ = oid_str;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_info.digest_ = {this->p_, this->p_ + tag};

  //TODO: Read hash
  this->p_ += tag;

  return content_info;
#endif
}


std::string SignatureParser::get_content_info_type(void) {
  LOG(DEBUG) << "Parse signed data - content info - content type";

  mbedtls_asn1_buf content_type_oid;
  int ret = 0;
  char oid_str[256] = { 0 };

  content_type_oid.tag = *this->p_;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.p = this->p_;

  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

  if (MBEDTLS_OID_CMP(MBEDTLS_SPC_INDIRECT_DATA_OBJID, &content_type_oid) != 0) {
    throw corrupted(std::string(oid_str) + " is not SPC_INDIRECT_DATA_OBJID");
  }
  LOG(DEBUG) << "contentType: " << oid_str << " (" << oid_to_string(oid_str) << ")";
  this->p_ += content_type_oid.len;

  return {oid_str};
}


void SignatureParser::parse_certificates(void) {
 LOG(DEBUG) << "Parsing Certificates (offset: "
             << std::dec << this->current_offset()
             << ")";

  int ret = 0;
  size_t tag;
  char buffer[1024];

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  uint8_t* cert_end = this->p_ + tag;
  while (this->p_ < cert_end) {
    std::memset(buffer, 0, sizeof(buffer));

    mbedtls_x509_crt* ca = new mbedtls_x509_crt{};
    mbedtls_x509_crt_init(ca);
    mbedtls_x509_crt_parse_der(ca, this->p_, this->end_ - this->p_);
    if (ca->raw.len <= 0) {
      break;
    }
    this->signature_.certificates_.emplace_back(ca);

    mbedtls_x509_crt_info(buffer, sizeof(buffer), "", ca);
    LOG(DEBUG) << std::endl << buffer << std::endl;

    this->p_ += ca->raw.len;
  }

}

AuthenticatedAttributes SignatureParser::get_authenticated_attributes(void) {
  LOG(DEBUG) << "Parsing authenticatedAttributes (offset: "
             << std::dec << this->current_offset()
             << ")";


  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };
  mbedtls_asn1_buf content_type_oid;

  AuthenticatedAttributes authenticated_attributes;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  // contentType (1.2.840.113549.1.9.3)
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  content_type_oid.tag = *this->p_;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }
  content_type_oid.p = this->p_;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

  LOG(DEBUG) << oid_str; // 1.2.840.113549.1.9.3 (PKCS #9 contentType)
  if (std::string(oid_str) != "1.2.840.113549.1.9.3") {
    throw corrupted("Authenticated attributes corrupted: Wrong Content type OID (" + std::string(oid_str) + ")");
  }

  this->p_ += content_type_oid.len;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  content_type_oid.tag = *this->p_;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  content_type_oid.p = this->p_;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  LOG(DEBUG) << oid_str; // 1.2.840.113549.1.9.4
  this->p_ += content_type_oid.len;
  //authenticated_attributes.content_type_ = oid_str;

  // TODO
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }
  this->p_ += tag;


  // messageDigest (Octet string)
  // |_ OID (PKCS #9 Message Disgest)
  // |_ SET -> OCTET STING
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LOG(DEBUG) << "Parsing messageDigest (offset: "
             << std::dec << this->current_offset()
             << ")";

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  content_type_oid.tag = *this->p_;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }
  content_type_oid.p = this->p_;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  LOG(DEBUG) << oid_str << " (" << oid_to_string(oid_str) << ")"; // 1.2.840.113549.1.9.4
  this->p_ += content_type_oid.len;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted: Can't read 'ASN1_OCTET_STRING'");
  }
  authenticated_attributes.message_digest_ = {this->p_, this->p_ + tag};
  this->p_ += tag;


  // SpcSpOpusInfo
  // |_ programName (utf16)
  // |_ moreInfo
  // ~~~~~~~~~~~~~~~~~~~~~~
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *this->p_;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.p = this->p_;
  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  LOG(DEBUG) << oid_str; // 1.3.6.1.4.1.311.2.1.12 (SpcSpOpusInfoObjId)
  this->p_ += content_type_oid.len;

  // programName
  // +++++++++++
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }
  LOG(DEBUG) << "Offset: " << std::dec << this->current_offset();
  LOG(DEBUG) << "Size: " << std::dec << tag;

  // u8 -> u16 due to endiness
  std::string u8progname{reinterpret_cast<char*>(this->p_), tag};
  std::u16string progname;
  try {
    utf8::unchecked::utf8to16(std::begin(u8progname), std::end(u8progname), std::back_inserter(progname));
  } catch (const utf8::exception&) {
    LOG(WARNING) << "utf8 error when parsing progname";
  }

  authenticated_attributes.program_name_ = progname;
  LOG(DEBUG) << "ProgName " << u16tou8(progname);
  this->p_ += tag;

  // moreInfo
  // ++++++++
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_BOOLEAN )) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  std::string more_info{reinterpret_cast<char*>(this->p_), tag}; // moreInfo
  authenticated_attributes.more_info_ = more_info;
  LOG(DEBUG) << more_info;
  this->p_ += tag;

  return authenticated_attributes;
}


SignerInfo SignatureParser::get_signer_info(void) {
  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };
  mbedtls_asn1_buf alg_oid;
  mbedtls_asn1_buf content_type_oid;

  SignerInfo signer_info;
  int32_t version;
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signer info corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signer info corrupted");
  }

  if ((ret = mbedtls_asn1_get_int(&(this->p_), this->end_, &version)) != 0) {
    throw corrupted("Signer info corrupted");
  }

  LOG(DEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "SignerInfo's version should be equal to 1 (" << std::dec << version << ")";
  signer_info.version_ = version;

  // issuerAndSerialNumber
  // ---------------------
  LOG(DEBUG) << "Parsing issuerAndSerialNumber (offset: "
             << std::dec << this->current_offset()
             << ")";

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signer info corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signer info corrupted");
  }

  // Name
  // ~~~~
  std::vector<std::pair<std::string, std::string>> issuer_name;
  uint8_t* p_end = this->p_ + tag;
  while(this->p_ < p_end) {
    if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
            MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
      throw corrupted("Signer info corrupted");
    }

    if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
            MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
      throw corrupted("Signer info corrupted");
    }

    content_type_oid.tag = *this->p_;

    if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
      throw corrupted("Signer info corrupted");
    }
    content_type_oid.p = this->p_;

    std::memset(oid_str, 0, sizeof(oid_str));
    mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

    LOG(DEBUG) << "Component ID: " << oid_str;
    this->p_ += content_type_oid.len;

    if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_PRINTABLE_STRING)) != 0) {
      throw corrupted("Signer info corrupted");
    }

    std::string name{reinterpret_cast<char*>(this->p_), tag};
    issuer_name.emplace_back(oid_str, name);
    LOG(DEBUG) << "Name: " << name;
    this->p_ += tag;
  }

  // CertificateSerialNumber (issuer SN)
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mbedtls_mpi certificate_number;
  mbedtls_mpi_init(&certificate_number);
  if ((ret = mbedtls_asn1_get_mpi(&(this->p_), this->end_, &certificate_number)) != 0) {
      throw corrupted("Signer info corrupted");
  }
  std::vector<uint8_t> certificate_sn(mbedtls_mpi_size(&certificate_number), 0);
  mbedtls_mpi_write_binary(&certificate_number, certificate_sn.data(), certificate_sn.size());
  mbedtls_mpi_free(&certificate_number);

  signer_info.issuer_ = {issuer_name, certificate_sn};



  // digestAlgorithm
  // ---------------
  LOG(DEBUG) << "Parsing digestAlgorithm (offset: "
             << std::dec << this->current_offset()
             << ")";
  if ((ret = mbedtls_asn1_get_alg_null(&(this->p_), this->end_, &alg_oid)) != 0) {
      throw corrupted("Signer info corrupted");
  }

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  LOG(DEBUG) << "signerInfo->digestAlgorithm " << oid_str;

  signer_info.digest_algorithm_ = oid_str;
  // authenticatedAttributes (IMPLICIT OPTIONAL)
  // |_ contentType
  // |_ messageDigest
  // |_ SpcSpOpusInfo
  // -----------------------

  try {
    signer_info.authenticated_attributes_ = this->get_authenticated_attributes();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // digestEncryptionAlgorithm
  // -------------------------
  if ((ret = mbedtls_asn1_get_alg_null(&(this->p_), this->end_, &alg_oid)) != 0) {
      throw corrupted("Signer info corrupted");
  }
  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  signer_info.signature_algorithm_ = oid_str;

  LOG(DEBUG) << "digestEncryptionAlgorithm: " << oid_str;

  // encryptedDigest
  // ---------------
  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
      throw corrupted("Signer info corrupted");
  }

  signer_info.encrypted_digest_ = {this->p_, this->p_ + tag};
  this->p_ += tag;

  //TODO:
  // unauthenticatedAttributes
  return signer_info;

}

void SignatureParser::parse_signature(void) {
  this->parse_header();

  // Version
  // =======
  int32_t version = this->get_signed_data_version();
  this->signature_.version_ = static_cast<uint32_t>(version);

  // Algo (digestAlgorithms)
  // =======================
  try {
    this->signature_.digest_algorithm_ = this->get_signed_data_digest_algorithms();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // contentInfo
  // |_ contentType
  // |_ content (SpcIndirectDataContent)
  // ===================================
  try {
    this->signature_.content_info_ = this->parse_content_info();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }

  // Certificates
  // ============
  try {
    this->parse_certificates();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }


  // signerInfo
  // ==========
  try {
    this->signature_.signer_info_ = this->get_signer_info();
  }
  catch (const corrupted& c) {
    LOG(ERROR) << c.what();
  }
  LOG(DEBUG) << "Signature: " << std::endl << this->signature_;
}


}
}


