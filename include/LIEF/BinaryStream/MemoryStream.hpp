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
#ifndef LIEF_MEMORY_STREAM_H
#define LIEF_MEMORY_STREAM_H

#include <vector>
#include <string>

#include "LIEF/BinaryStream/BinaryStream.hpp"

namespace LIEF {
class Binary;
class MemoryStream : public BinaryStream {
  public:
  MemoryStream() = delete;
  MemoryStream(uintptr_t base_address);
  MemoryStream(uintptr_t base_address, uint64_t size);

  inline uintptr_t base_address() const {
    return this->baseaddr_;
  }

  inline uint64_t end() const {
    return this->baseaddr_ + this->size_;
  }

  inline STREAM_TYPE type() const override {
    return STREAM_TYPE::MEMORY;
  }

  inline void binary(Binary& bin) {
    this->binary_ = &bin;
  }

  inline Binary* binary() {
    return this->binary_;
  }

  virtual uint64_t size(void) const override;

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

  virtual ~MemoryStream();


  protected:
  virtual const void* read_at(uint64_t offset, uint64_t size, bool throw_error = true) const override;
  uintptr_t baseaddr_ = 0;
  uint64_t size_ = 0;
  Binary* binary_ = nullptr;
};
}

#endif
