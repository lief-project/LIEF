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

#include "utf8.h"
#include "LIEF/utils.hpp"

#include "LIEF/logging++.hpp"

#include "pkcs7.h"

#include <cstring>

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

  const uint8_t* sig = this->stream_->peek_array<uint8_t>(8, this->stream_->size() - 8, /* check */false);
  if (sig != nullptr) {
    this->signature_ptr_ = sig;
    this->end_ = this->signature_ptr_ + this->stream_->size() - 8;
    this->p_ = const_cast<uint8_t*>(this->signature_ptr_);
    try {
      this->parse_signature();
    } catch (const std::exception& e) {
      VLOG(VDEBUG) << e.what();
    }
  }
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
  VLOG(VDEBUG) << "OID (signedData): " << oid_str;
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
  VLOG(VDEBUG) << "Parse signed data - version";
  int ret = 0;

  int32_t version;
  if ((ret = mbedtls_asn1_get_int(&(this->p_), this->end_, &version)) != 0) {
    throw corrupted("Signature corrupted");
  }

  VLOG(VDEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "Version should be equal to 1 (" << std::dec << version << ")";
  return version;
}


std::string SignatureParser::get_signed_data_digest_algorithms(void) {
  VLOG(VDEBUG) << "Parse signed data - digest algorithm";
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

  VLOG(VDEBUG) << "digestAlgorithms: " << oid_str;
  return oid_str;

}


ContentInfo SignatureParser::parse_content_info(void) {
  VLOG(VDEBUG) << "Parse signed data - content info";

  mbedtls_asn1_buf content_type_oid;
  mbedtls_asn1_buf alg_oid;
  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };

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
  VLOG(VDEBUG) << "Parsing SpcIndirectDataContent (offset: "
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

  // Save off raw now so that it covers everything else in the ContentInfo
  content_info.raw_ = {this->p_, this->p_ + tag};

  // SpcAttributeTypeAndOptionalValue
  // |_ SPC_PE_IMAGE_DATAOBJ
  // |_ SpcPeImageData
  // ++++++++++++++++++++++++++++++++
  VLOG(VDEBUG) << "Parsing SpcAttributeTypeAndOptionalValue (offset: "
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
  VLOG(VDEBUG) << "SpcAttributeTypeAndOptionalValue->type " << oid_str;

  content_info.type_ = oid_str;
  this->p_ += content_type_oid.len;

  // SpcPeImageData
  // |_ SpcPeImageFlags
  // |_ SpcLink
  // ++++++++++++++
  VLOG(VDEBUG) << "Parsing SpcPeImageData (offset: "
             << std::dec << this->current_offset()
             << ")";

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // SpcPeImageFlags
  // ^^^^^^^^^^^^^^^
  VLOG(VDEBUG) << "Parsing SpcPeImageFlags (offset: "
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
  VLOG(VDEBUG) << "DigestInfo->digestAlgorithm: " << oid_str;

  content_info.digest_algorithm_ = oid_str;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_info.digest_ = {this->p_, this->p_ + tag};

  //TODO: Read hash
  this->p_ += tag;

  return content_info;
}


std::string SignatureParser::get_content_info_type(void) {
  VLOG(VDEBUG) << "Parse signed data - content info - content type";

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
  VLOG(VDEBUG) << "contentType: " << oid_str << " (" << oid_to_string(oid_str) << ")";
  this->p_ += content_type_oid.len;

  return {oid_str};
}


void SignatureParser::parse_certificates(void) {
 VLOG(VDEBUG) << "Parsing Certificates (offset: "
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

    std::unique_ptr<mbedtls_x509_crt> ca{new mbedtls_x509_crt{}};
    mbedtls_x509_crt_init(ca.get());
    mbedtls_x509_crt_parse_der(ca.get(), this->p_, this->end_ - this->p_);
    if (ca->raw.len <= 0) {
      break;
    }

    mbedtls_x509_crt_info(buffer, sizeof(buffer), "", ca.get());
    VLOG(VDEBUG) << std::endl << buffer << std::endl;

    this->signature_.certificates_.emplace_back(ca.get());
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


  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };
  mbedtls_asn1_buf content_type_oid;

  AuthenticatedAttributes authenticated_attributes;

  uint8_t *p_start = this->p_;

  if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Authenticated attributes corrupted");
  }

  authenticated_attributes.raw_ = {p_start, p_start + (this->p_ - p_start) + tag};

  uint8_t* p_end = this->p_ + tag;
  while(this->p_ < p_end) {
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

    this->p_ += content_type_oid.len;

    if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
            MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
      throw corrupted("Authenticated attributes corrupted");
    }

    if (std::string(oid_str) == "1.2.840.113549.1.9.3") {
      // contentType
      // |_ OID (PKCS #9 Message Digest)
      // |_ SET -> OID
      // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      VLOG(VDEBUG) << "Parsing contentType (offset: "
                 << std::dec << this->current_offset()
                 << ")";
      content_type_oid.tag = *this->p_;
      if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
        throw corrupted("Authenticated attributes corrupted");
      }
      content_type_oid.p = this->p_;

      std::memset(oid_str, 0, sizeof(oid_str));
      mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
      authenticated_attributes.content_type_ = oid_str;
      this->p_ += content_type_oid.len;
      continue;

    } else if (std::string(oid_str) == "1.2.840.113549.1.9.4") {
      // messageDigest (Octet string)
      // |_ OID (PKCS #9 Message Digest)
      // |_ SET -> OCTET STING
      // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      VLOG(VDEBUG) << "Parsing messageDigest (offset: "
                 << std::dec << this->current_offset()
                 << ")";
      VLOG(VDEBUG) << oid_str << " (" << oid_to_string(oid_str) << ")"; // 1.2.840.113549.1.9.4

      if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        throw corrupted("Signature corrupted: Can't read 'ASN1_OCTET_STRING'");
      }
      authenticated_attributes.message_digest_ = {this->p_, this->p_ + tag};
      this->p_ += tag;
      continue;

    } else if (std::string(oid_str) == "1.3.6.1.4.1.311.2.1.12") {
      // SpcSpOpusInfo
      // |_ programName (utf16)
      // |_ moreInfo
      // ~~~~~~~~~~~~~~~~~~~~~~
      if ((ret = mbedtls_asn1_get_tag(&(this->p_), this->end_, &tag,
              MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
        throw corrupted("Authenticated attributes corrupted");
      }

      if (tag == 0) {
          VLOG(VDEBUG) << "No program name or more info specified ";
          authenticated_attributes.program_name_ = u"";
          authenticated_attributes.more_info_ = "";
          continue;
      }

      uint8_t *seq_end = this->p_ + tag;

      if (*this->p_ == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) {
          this->p_ += 1;
          if ((ret = mbedtls_asn1_get_len(&(this->p_), this->end_, &tag)) != 0) {
            VLOG(VDEBUG) << "Unexpected format for SpcSpOpusInfo [0] block ";
            throw corrupted("Authenticated attributes corrupted");
          }

          // Two cases to handle here:
          // SpcString ::= CHOICE {
          //   unicode [0] IMPLICIT BMPSTRING,
          //   ascii   [1] IMPLICIT IA5STRING
          // }

          if (*this->p_ == (MBEDTLS_ASN1_CONTEXT_SPECIFIC) ||
              *this->p_ == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)) {
            this->p_ += 1;
            if ((ret = mbedtls_asn1_get_len(&(this->p_), this->end_, &tag)) != 0) {
              VLOG(VDEBUG) << "Unexpected format for SpcString block ";
              throw corrupted("Authenticated attributes corrupted");
            }

            VLOG(VDEBUG) << "Offset: " << std::dec << this->current_offset();
            VLOG(VDEBUG) << "Size: " << std::dec << tag;

            // u8 -> u16 due to endiness
            std::string u8progname{reinterpret_cast<char*>(this->p_), tag};
            std::u16string progname;
            try {
              utf8::unchecked::utf8to16(std::begin(u8progname), std::end(u8progname), std::back_inserter(progname));
            } catch (const utf8::exception&) {
              LOG(WARNING) << "utf8 error when parsing progname";
            }

            authenticated_attributes.program_name_ = progname;
            VLOG(VDEBUG) << "ProgName " << u16tou8(progname);
            this->p_ += tag;

          } else {
            VLOG(VDEBUG) << "Unexpected format for SpcString block ";
            throw corrupted("Authenticated attributes corrupted");
          }

          if (this->p_ >= seq_end) {
              VLOG(VDEBUG) << "No more info specified ";
              authenticated_attributes.more_info_ = "";
              continue;
          }

      } else {
          VLOG(VDEBUG) << "No program name specified ";
          authenticated_attributes.program_name_ = u"";
      }

      // moreInfo
      // ++++++++
      if (*this->p_ == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_BOOLEAN)) {
          this->p_ += 1;
          if ((ret = mbedtls_asn1_get_len(&(this->p_), this->end_, &tag)) != 0) {
            VLOG(VDEBUG) << "Unexpected format for SpcSpOpusInfo [1] block ";
            throw corrupted("Authenticated attributes corrupted");
          }

          uint8_t p_val = *this->p_;

          this->p_ += 1;
          if ((ret = mbedtls_asn1_get_len(&(this->p_), this->end_, &tag)) != 0) {
            VLOG(VDEBUG) << "Unexpected format for SpcLink block ";
            throw corrupted("Authenticated attributes corrupted");
          }

          // Three cases to handle here:
          // SpcLink ::= CHOICE {
          //   url                     [0] IMPLICIT IA5STRING,
          //   moniker                 [1] IMPLICIT SpcSerializedObject,
          //   file                    [2] EXPLICIT SpcString
          // }

          if (p_val == (MBEDTLS_ASN1_CONTEXT_SPECIFIC)) {

            std::string more_info{reinterpret_cast<char*>(this->p_), tag}; // moreInfo
            authenticated_attributes.more_info_ = more_info;
            VLOG(VDEBUG) << more_info;
            this->p_ += tag;

          } else if (p_val == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)) {
            VLOG(VDEBUG) << "Parsing MoreInfo 'moniker' option not currently supported ";
            authenticated_attributes.more_info_ = "";

          } else if (p_val == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2)) {
            VLOG(VDEBUG) << "Parsing MoreInfo 'file' option not currently supported ";
            authenticated_attributes.more_info_ = "";

          } else {
            VLOG(VDEBUG) << "Unexpected format for SpcLink block ";
            throw corrupted("Authenticated attributes corrupted");
          }
          continue;
      }

    } else {
      VLOG(VDEBUG) << "Skipping OID " << oid_str;
      this->p_ += tag;
      continue;
    }
  }

  return authenticated_attributes;
}


SignerInfo SignatureParser::get_signer_info(void) {
  int ret = 0;
  size_t tag;
  char oid_str[256] = { 0 };
  mbedtls_asn1_buf alg_oid;

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

  VLOG(VDEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "SignerInfo's version should be equal to 1 (" << std::dec << version << ")";
  signer_info.version_ = version;

  // issuerAndSerialNumber
  // ---------------------
  VLOG(VDEBUG) << "Parsing issuerAndSerialNumber (offset: "
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
  mbedtls_x509_name name;
  char buffer[1024];

  uint8_t* p_end = this->p_ + tag;

  std::memset(&name, 0, sizeof(name));
  if ((ret = mbedtls_x509_get_name(&(this->p_), p_end, &name)) != 0) {
    throw corrupted("Signer info corrupted");
  }

  mbedtls_x509_dn_gets(buffer, sizeof(buffer), &name);

  std::string issuer_name {buffer};

  VLOG(VDEBUG) << "Issuer: " << issuer_name;

  mbedtls_x509_name *name_cur;

  name_cur = name.next;
  while( name_cur != NULL )
  {
    mbedtls_x509_name *name_prv = name_cur;
    name_cur = name_cur->next;
    mbedtls_free( name_prv );
  }

  // CertificateSerialNumber (issuer SN)
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mbedtls_x509_buf serial;
  if ((ret = mbedtls_x509_get_serial(&(this->p_), this->end_, &serial)) != 0) {
      throw corrupted("Signer info corrupted");
  }
  std::vector<uint8_t> certificate_sn = {serial.p, serial.p + serial.len};

  signer_info.issuer_ = {issuer_name, certificate_sn};

  // digestAlgorithm
  // ---------------
  VLOG(VDEBUG) << "Parsing digestAlgorithm (offset: "
             << std::dec << this->current_offset()
             << ")";
  if ((ret = mbedtls_asn1_get_alg_null(&(this->p_), this->end_, &alg_oid)) != 0) {
      throw corrupted("Signer info corrupted");
  }

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  VLOG(VDEBUG) << "signerInfo->digestAlgorithm " << oid_str;

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

  VLOG(VDEBUG) << "digestEncryptionAlgorithm: " << oid_str;

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
  VLOG(VDEBUG) << "Signature: " << std::endl << this->signature_;
}


}
}


