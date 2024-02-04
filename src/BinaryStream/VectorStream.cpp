/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <array>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>

#include <mbedtls/platform.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "logging.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

namespace LIEF {

VectorStream::VectorStream(VectorStream&& other) = default;
VectorStream& VectorStream::operator=(VectorStream&& other) = default;

result<VectorStream> VectorStream::from_file(const std::string& file) {
  std::ifstream ifs(file, std::ios::in | std::ios::binary);
  if (!ifs) {
    LIEF_ERR("Can't open '{}'", file);
    return make_error_code(lief_errors::read_error);
  }

  ifs.unsetf(std::ios::skipws);
  ifs.seekg(0, std::ios::end);
  const auto size = static_cast<uint64_t>(ifs.tellg());
  ifs.seekg(0, std::ios::beg);
  std::vector<uint8_t> data;
  data.resize(size, 0);
  ifs.read(reinterpret_cast<char*>(data.data()), data.size());
  return VectorStream{std::move(data)};
}


VectorStream::VectorStream(std::vector<uint8_t> data) :
  binary_{std::move(data)},
  size_{binary_.size()}
{
  stype_ = STREAM_TYPE::VECTOR;
}

result<const void*> VectorStream::read_at(uint64_t offset, uint64_t size) const {
  const uint64_t stream_size = this->size();
  if (offset > stream_size || (offset + size) > stream_size) {
    size_t out_size = (offset + size) - stream_size;
    LIEF_DEBUG("Can't read #{:d} bytes at 0x{:04x} (0x{:x} bytes out of bound)", size, offset, out_size);
    return make_error_code(lief_errors::read_error);
  }
  return binary_.data() + offset;
}

const std::vector<uint8_t>& VectorStream::content() const {
  return binary_;
}

bool VectorStream::classof(const BinaryStream& stream) {
  return stream.type() == STREAM_TYPE::VECTOR;
}
}

