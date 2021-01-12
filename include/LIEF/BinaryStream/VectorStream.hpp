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
#ifndef VECTOR_BINARY_STREAM_H
#define VECTOR_BINARY_STREAM_H

#include <vector>
#include <string>

#include "LIEF/BinaryStream/BinaryStream.hpp"
namespace LIEF {
class VectorStream : public BinaryStream {
  public:
  //using BinaryStream::read_integer;
  VectorStream(const std::string& filename);
  VectorStream(const std::vector<uint8_t>& data);

  virtual uint64_t size(void) const override;

  const std::vector<uint8_t>& content(void) const;

  inline uint8_t* p() {
    return this->binary_.data() + this->pos();
  }

  inline const uint8_t* p() const {
    return this->binary_.data() + this->pos();
  }


  inline uint8_t* start() {
    return this->binary_.data();
  }

  inline const uint8_t* start() const {
    return this->binary_.data();
  }

  inline uint8_t* end() {
    return this->binary_.data() + this->binary_.size();
  }

  inline const uint8_t* end() const {
    return this->binary_.data() + this->binary_.size();
  }

  virtual result<size_t> asn1_read_tag(int tag) override;
  virtual result<size_t> asn1_read_len() override;
  result<size_t> asn1_peek_len();
  virtual result<std::string> asn1_read_alg() override;
  virtual result<std::string> asn1_read_oid() override;
  virtual result<int32_t> asn1_read_int() override;
  virtual result<std::vector<uint8_t>> asn1_read_bitstring() override;
  virtual result<std::vector<uint8_t>> asn1_read_octet_string() override;
  virtual result<std::unique_ptr<mbedtls_x509_crt>> asn1_read_cert() override;
  virtual result<std::string> x509_read_names() override;
  virtual result<std::vector<uint8_t>> x509_read_serial() override;
  virtual result<std::unique_ptr<mbedtls_x509_time>> x509_read_time() override;

  protected:
  virtual const void* read_at(uint64_t offset, uint64_t size, bool throw_error = true) const override;
  std::vector<uint8_t> binary_;
  uint64_t size_;
};
}

#endif
