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
#ifndef LIEF_PE_SIGNATURE_UTILS_H_
#define LIEF_PE_SIGNATURE_UTILS_H_

#include <string>
#include <memory>

#include "LIEF/PE/signature/types.hpp"
#include "mbedtls/x509_crt.h"

namespace LIEF {
namespace PE {

#define ASN1_GET_TAG(p, end, len, tag, msg) \
  do {                                      \
    int ret = 0;                                       \
    if ((ret = mbedtls_asn1_get_tag(&(p), (end), &(len), \
      tag)) != 0) { \
      throw corrupted(msg);\
    } \
  } while (0)\

std::string get_spc_string(uint8_t*&p, const uint8_t* end);
spc_serialized_object_t get_spc_serialized_object(uint8_t*&p, const uint8_t* end);
spc_link_t get_spc_link(uint8_t*&p, const uint8_t* end);
std::string get_oid_numeric_str(uint8_t*& p, const uint8_t* end);
size_t get_next_content_len(uint8_t*& p, const uint8_t* end, int tag);
std::string get_algorithm_identifier_oid(uint8_t*& p, const uint8_t* end);
std::unique_ptr<mbedtls_x509_crt> get_x509_crt(uint8_t*&p, const uint8_t* end);
std::string get_issuer_name(uint8_t*& p, const uint8_t* end);
void free_mbedtls_x509_name(mbedtls_x509_name& name);
std::ostream& operator<<(std::ostream& os, const spc_link_t& spc_link);

}
}

#endif
