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

#include <iomanip>

#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform.h>

#include "utf8.h"
#include "LIEF/utils.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/logging++.hpp"
#include "LIEF/PE/signature/SignatureUtils.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

namespace LIEF {
namespace PE {

std::ostream& operator<<(std::ostream& os, const spc_link_t& spc_link) {
  constexpr uint8_t wsize = 30;
  if (spc_link.first == "url" || spc_link.first == "file") {
    os << std::setw(wsize) << std::setfill(' ')
       << spc_link.first << ": "
       << mapbox::util::get<std::string>(spc_link.second) << std::endl;
  } else {
    // TODO: print SpcSerializedObject
    os << spc_link.first << std::endl;
  }
  return os;
}

std::string get_spc_string(uint8_t*& p, const uint8_t* end) {
  /*
   * SpcString ::= CHOICE {
   *   unicode [0] IMPLICIT BMPSTRING,
   *   ascii   [1] IMPLICIT IA5STRING
   * }
   */
  const auto tag = *p;
  if (tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC) &&
      tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)) {
    throw corrupted("Invalid SpcString");
  }

  size_t len = 0;
  p += 1;
  if (mbedtls_asn1_get_len(&p, end, &len) != 0) {
    VLOG(VDEBUG) << "Unexpected format for SpcString block";
    throw corrupted("Invalid SpcString");
  }

  if (tag == MBEDTLS_ASN1_CONTEXT_SPECIFIC) {
    std::u16string u16_spc_string(len / 2, '0');
    auto u16p = reinterpret_cast<int16_t*>(p);
    for (size_t i = 0; i < len / 2; i++) {
      u16_spc_string[i] = swap_endian(u16p[i]);
    }
    p += len;
    return u16tou8(u16_spc_string);
  }

  std::string spc_string(reinterpret_cast<char*>(p), len);
  p += len;
  return spc_string;
}

spc_serialized_object_t get_spc_serialized_object(uint8_t*& p, const uint8_t* end) {
  /*
   * SpcSerializedObject ::= SEQUENCE {
   *   classId SpcUuid,
   *   serializedData OCTETSTRING
   * }
   *
   * SpcUuid ::= OCTETSTRING
   */
  size_t len = 0;
  ASN1_GET_TAG(p, end, len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, "SpcSerializedObject is corrupted");

  len = get_next_content_len(p, end, MBEDTLS_ASN1_OCTET_STRING);
  std::vector<uint8_t> class_id = {p, p + len};
  p += len;

  len = get_next_content_len(p, end, MBEDTLS_ASN1_OCTET_STRING);
  std::vector<uint8_t> serialized_data = {p, p + len};
  p += len;

  return std::make_pair<>(class_id, serialized_data);
}

spc_link_t get_spc_link(uint8_t*& p, const uint8_t* end) {
  /*
   * SpcLink ::= CHOICE {
   *   url                     [0] IMPLICIT IA5STRING,
   *   moniker                 [1] IMPLICIT SpcSerializedObject,
   *   file                    [2] EXPLICIT SpcString
   * }
   *
   * SpcString ::= CHOICE {
   *   unicode  [0] IMPLICIT BMPSTRING,
   *   ascii    [1] IMPLICIT IA5STRING
   * }
   */
  size_t len = 0;
  const auto tag = *p;
  p += 1;
  if (mbedtls_asn1_get_len(&(p), end, &len) != 0) {
    throw corrupted("SpcLink is corrupted");
  }

  switch (tag) {
    case MBEDTLS_ASN1_CONTEXT_SPECIFIC:
      {
        const auto url_str = std::string(reinterpret_cast<char*>(p), len);
        p += len;
        return {"url", url_str};
      }
    case MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1:
      return {"moniker", get_spc_serialized_object(p, end)};
    case MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2:
      return {"file", get_spc_string(p, end)};
    default:
      VLOG(VDEBUG) << "tag: " << std::hex << tag;
      throw corrupted("SpcLink is corrupted");
  }
}

std::string get_oid_numeric_str(uint8_t*& p, const uint8_t* end) {
  mbedtls_asn1_buf buf{};
  char oid_str[256] = { 0 };

  buf.tag = *p;
  ASN1_GET_TAG(p, end, buf.len, MBEDTLS_ASN1_OID, "Error while reading OID");
  buf.p = p;

  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &buf);
  VLOG(VDEBUG) << "OID: " << oid_str << " (" << oid_to_string(oid_str) << ")";
  p += buf.len;

  return oid_str;
}

std::string get_algorithm_identifier_oid(uint8_t*& p, const uint8_t* end) {
  char oid_str[256] = { 0 };
  mbedtls_asn1_buf alg_oid;
  if (mbedtls_asn1_get_alg_null(&p, end, &alg_oid) != 0) {
    return "";
  }
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  return oid_str;
}

size_t get_next_content_len(uint8_t*& p, const uint8_t* end, int tag) {
  size_t len = 0;
  ASN1_GET_TAG(p, end, len, tag, "Cannot get next content length");
  return len;
}

std::unique_ptr<mbedtls_x509_crt> get_x509_crt(uint8_t*& p, const uint8_t* end) {
  auto ca = std::make_unique<mbedtls_x509_crt>();
  mbedtls_x509_crt_init(ca.get());
  mbedtls_x509_crt_parse_der(ca.get(), p, end - p);
  if (ca->raw.len <= 0) {
    return nullptr;
  }

  char buffer[1024] = {0};
  mbedtls_x509_crt_info(buffer, sizeof(buffer), "", ca.get());
  VLOG(VDEBUG) << std::endl << buffer << std::endl;

  return ca;
}

std::string get_issuer_name(uint8_t*& p, const uint8_t* end) {
  mbedtls_x509_name name {};
  char buffer[1024] = { 0 };

  if (mbedtls_x509_get_name(&p, end, &name) != 0) {
    return "";
  }
  mbedtls_x509_dn_gets(buffer, sizeof(buffer), &name);
  free_mbedtls_x509_name(name);
  return buffer;
}

void free_mbedtls_x509_name(mbedtls_x509_name& name) {
  mbedtls_x509_name *  name_cur = name.next;
  while( name_cur != NULL ) {
    mbedtls_x509_name *name_prv = name_cur;
    name_cur = name_cur->next;
    mbedtls_free( name_prv );
  }
}

}
}


