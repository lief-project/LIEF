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
#ifndef VECTOR_BINARY_STREAM_H
#define VECTOR_BINARY_STREAM_H

#include <vector>
#include <string>

#include "LIEF/errors.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"
namespace LIEF {
class VectorStream : public BinaryStream {
  public:
  static result<VectorStream> from_file(const std::string& file);
  VectorStream(std::vector<uint8_t> data);

  VectorStream() = delete;

  // VectorStream should not be copyable for performances reasons
  VectorStream(const VectorStream&) = delete;
  VectorStream& operator=(const VectorStream&) = delete;

  VectorStream(VectorStream&& other);
  VectorStream& operator=(VectorStream&& other);

  inline uint64_t size() const override {
    return size_;
  }

  const std::vector<uint8_t>& content() const;

  inline std::vector<uint8_t>&& move_content() {
    size_ = 0;
    return std::move(binary_);
  }

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

  result<size_t> asn1_read_tag(int tag) override;
  result<size_t> asn1_read_len() override;
  result<std::string> asn1_read_alg() override;
  result<std::string> asn1_read_oid() override;
  result<int32_t> asn1_read_int() override;
  result<std::vector<uint8_t>> asn1_read_bitstring() override;
  result<std::vector<uint8_t>> asn1_read_octet_string() override;
  result<std::unique_ptr<mbedtls_x509_crt>> asn1_read_cert() override;
  result<std::string> x509_read_names() override;
  result<std::vector<uint8_t>> x509_read_serial() override;
  result<std::unique_ptr<mbedtls_x509_time>> x509_read_time() override;

  static bool classof(const BinaryStream& stream);

  protected:
  result<const void*> read_at(uint64_t offset, uint64_t size) const override;
  std::vector<uint8_t> binary_;
  uint64_t size_ = 0; // Original size without alignment
};
}

#endif
