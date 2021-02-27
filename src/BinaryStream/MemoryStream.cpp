/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include <iterator>
#include <vector>
#include <string>
#include <fstream>
#include <cassert>
#include <sstream>
#include <algorithm>

#include <mbedtls/platform.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "logging.hpp"

#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/BinaryStream/MemoryStream.hpp"
#include "LIEF/exception.hpp"
namespace LIEF {


MemoryStream::MemoryStream(uintptr_t base_address) :
  baseaddr_{base_address},
  size_{-1llu}
{}

MemoryStream::MemoryStream(uintptr_t base_address, uint64_t size) :
  baseaddr_{base_address},
  size_{size}
{}

uint64_t MemoryStream::size(void) const {
  return this->size_;
}

const void* MemoryStream::read_at(uint64_t offset, uint64_t, bool) const {
  const uintptr_t va = this->baseaddr_ + offset;
  if (this->binary_ != nullptr) {
    return reinterpret_cast<const void*>(this->binary_->offset_to_virtual_address(offset, this->baseaddr_));
  }
  return reinterpret_cast<const void*>(va);
}


result<size_t> MemoryStream::asn1_read_tag(int tag) {
  // TODO(romain)
  return 0;
}

result<size_t> MemoryStream::asn1_peek_len() {
  // TODO(romain)
  return 0;
}

result<size_t> MemoryStream::asn1_read_len() {
  // TODO(romain)
  return 0;
}

result<std::string> MemoryStream::asn1_read_alg() {
  // TODO(romain)
  return std::string();
}

result<std::string> MemoryStream::asn1_read_oid() {
  // TODO(romain)
  return std::string();
}


result<int32_t> MemoryStream::asn1_read_int() {
  // TODO(romain)
  return 0;
}

result<std::vector<uint8_t>> MemoryStream::asn1_read_bitstring() {
  // TODO(romain)
  return {};
}


result<std::vector<uint8_t>> MemoryStream::asn1_read_octet_string() {
  // TODO(romain)
  return {};
}

result<std::unique_ptr<mbedtls_x509_crt>> MemoryStream::asn1_read_cert() {
  // TODO(romain)
  return std::unique_ptr<mbedtls_x509_crt>{nullptr};
}

result<std::string> MemoryStream::x509_read_names() {
  // TODO(romain)
  return std::string();
}

result<std::vector<uint8_t>> MemoryStream::x509_read_serial() {
  // TODO(romain)
  return {};
}

result<std::unique_ptr<mbedtls_x509_time>> MemoryStream::x509_read_time() {
  // TODO(romain)
  return std::unique_ptr<mbedtls_x509_time>{nullptr};
}

MemoryStream::~MemoryStream() = default;

}

