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

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/exception.hpp"
namespace LIEF {

inline void free_names(mbedtls_x509_name& names) {
  mbedtls_x509_name *name_cur;
  name_cur = names.next;
  while (name_cur != nullptr) {
    mbedtls_x509_name *name_prv = name_cur;
    name_cur = name_cur->next;
    mbedtls_free(name_prv);
  }
}

VectorStream::VectorStream(const std::string& filename) {
  std::ifstream binary(filename, std::ios::in | std::ios::binary);

  if (binary) {
    binary.unsetf(std::ios::skipws);
    binary.seekg(0, std::ios::end);
    assert(binary.tellg() > 0);
    this->size_ = static_cast<uint64_t>(binary.tellg());
    binary.seekg(0, std::ios::beg);

    // reserve capacity
    this->binary_.resize(this->size() + 30, 0);
    binary.read(reinterpret_cast<char*>(binary_.data()), this->size_);
    binary.close();
  } else {
    throw LIEF::bad_file("Unable to open " + filename);
  }
}


VectorStream::VectorStream(const std::vector<uint8_t>& data) :
  binary_{data},
  size_{data.size()}
{}


uint64_t VectorStream::size(void) const {
  return this->size_;
}


const void* VectorStream::read_at(uint64_t offset, uint64_t size, bool throw_error) const {

  if (offset > this->size() or (offset + size) > this->size()) {
    size_t out_size = (offset + size) - this->size();
    LIEF_DEBUG("Can't read #{:d} bytes at 0x{:04x} (0x{:x} bytes out of bound)", size, offset, out_size);
    if (throw_error) {
      throw LIEF::read_out_of_bound(offset, size);
    }
    return nullptr;
  }
  return this->binary_.data() + offset;
}


result<size_t> VectorStream::asn1_read_tag(int tag) {
  size_t out = 0;

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_asn1_get_tag(&p, end, &out, tag);

  if (ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  else if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
    return make_error_code(lief_errors::asn1_bad_tag);
  }
  else if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return out;
}

result<size_t> VectorStream::asn1_peek_len() {
  const uint64_t pos = this->pos();
  auto len = this->asn1_read_len();
  this->setpos(pos);
  return len;
}

result<size_t> VectorStream::asn1_read_len() {
  size_t len = 0;

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_asn1_get_len(&p, end, &len);

  if (ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  else if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return len;
}

result<std::string> VectorStream::asn1_read_alg() {
  mbedtls_asn1_buf alg_oid;
  char oid_str[256] = {0};

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid);

  if (ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  else if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  ret = mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  if (ret <= 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return std::string(oid_str);
}

result<std::string> VectorStream::asn1_read_oid() {
  mbedtls_asn1_buf buf;
  char oid_str[256] = {0};

  auto len = this->asn1_read_tag(MBEDTLS_ASN1_OID);
  if (not len) {
    return len.error();
  }

  buf.len = len.value();
  buf.p   = this->p();
  buf.tag = MBEDTLS_ASN1_OID;

  int ret = mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &buf);
  if (ret == MBEDTLS_ERR_OID_BUF_TOO_SMALL) {
    LIEF_DEBUG("asn1_read_oid: mbedtls_oid_get_numeric_string return MBEDTLS_ERR_OID_BUF_TOO_SMALL");
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(buf.len);
  return std::string(oid_str);
}


result<int32_t> VectorStream::asn1_read_int() {
  int32_t value = 0;

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_asn1_get_int(&p, end, &value);

  if (ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  else if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return value;
}

result<std::vector<uint8_t>> VectorStream::asn1_read_bitstring() {
  mbedtls_asn1_bitstring bs = {0, 0, nullptr};

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_asn1_get_bitstring(&p, end, &bs);

  if (ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  else if (ret == MBEDTLS_ERR_ASN1_LENGTH_MISMATCH) {
    this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
    return std::vector<uint8_t>{bs.p, bs.p + bs.len};
  }
  else if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return std::vector<uint8_t>{bs.p, bs.p + bs.len};
}


result<std::vector<uint8_t>> VectorStream::asn1_read_octet_string() {
  auto tag = this->asn1_read_tag(MBEDTLS_ASN1_OCTET_STRING);
  if (not tag) {
    return tag.error();
  }
  std::vector<uint8_t> raw = {this->p(), this->p() + tag.value()};
  this->increment_pos(tag.value());
  return raw;
}

result<std::unique_ptr<mbedtls_x509_crt>> VectorStream::asn1_read_cert() {
  std::unique_ptr<mbedtls_x509_crt> ca{new mbedtls_x509_crt{}};
  mbedtls_x509_crt_init(ca.get());

  uint8_t* p               = this->p();
  const uint8_t* end       = this->end();
  const uintptr_t buff_len = reinterpret_cast<uintptr_t>(end) - reinterpret_cast<uintptr_t>(p);

  int ret = mbedtls_x509_crt_parse_der(ca.get(), p, /* buff len */ buff_len);
  if (ret != 0) {
    std::string strerr(1024, 0);
    mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
    LIEF_DEBUG("asn1_read_cert(): {}", strerr);
    return make_error_code(lief_errors::read_error);
  }
  if (ca->raw.len <= 0) {
    return make_error_code(lief_errors::read_error);
  }
  this->increment_pos(ca->raw.len);
  return ca;
}

result<std::string> VectorStream::x509_read_names() {
  mbedtls_x509_name name;
  std::memset(&name, 0, sizeof(name));

  auto tag = this->asn1_read_tag(/* Name */
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (not tag) {
    LIEF_INFO("Wrong tag: 0x{:x} for x509_read_names (pos: {:d})",
        this->peek<uint8_t>(), this->pos());
    return tag.error();
  }

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = p + tag.value();
  int ret = mbedtls_x509_get_name(&p, end, &name);
  if (ret != 0) {
    free_names(name);
    LIEF_DEBUG("mbedtls_x509_get_name failed with {:d}", ret);
    return make_error_code(lief_errors::read_error);
  }
  char buffer[1024];
  ret = mbedtls_x509_dn_gets(buffer, sizeof(buffer), &name);
  free_names(name);

  if (ret < 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return std::string(buffer);
}

result<std::vector<uint8_t>> VectorStream::x509_read_serial() {
  mbedtls_x509_buf serial;

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_x509_get_serial(&p, end, &serial);

  if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return std::vector<uint8_t>{serial.p, serial.p + serial.len};
}

result<std::unique_ptr<mbedtls_x509_time>> VectorStream::x509_read_time() {
  std::unique_ptr<mbedtls_x509_time> tm{new mbedtls_x509_time{}};

  const uint8_t* cur_p = this->p();
  uint8_t* p           = this->p();
  const uint8_t* end   = this->end();

  int ret = mbedtls_x509_get_time(&p, end, tm.get());

  if (ret != 0) {
    return make_error_code(lief_errors::read_error);
  }

  this->increment_pos(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(cur_p));
  return std::move(tm);
}



const std::vector<uint8_t>& VectorStream::content(void) const {
  return this->binary_;
}
}

