/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "internal_utils.hpp"
#include "logging.hpp"

namespace LIEF {

result<VectorStream> VectorStream::from_file(std::string_view file) {
  std::ifstream ifs(std::string(file), std::ios::in | std::ios::binary);
  if (!ifs) {
    LIEF_ERR("Failed to open '{}'", file);
    return make_error_code(lief_errors::read_error);
  }

  ifs.unsetf(std::ios::skipws);
  auto size = istream_size(ifs);
  if (!size) {
    LIEF_ERR("Failed to determine the size of '{}'", file);
    return make_error_code(size.error());
  }

  std::vector<uint8_t> data(*size, 0);
  ifs.read(reinterpret_cast<char*>(data.data()), data.size());

  if ((size_t)ifs.gcount() != *size) {
    LIEF_ERR("Can't read the content of '{}'", file);
    return make_error_code(lief_errors::read_error);
  }

  return VectorStream{std::move(data)};
}

std::unique_ptr<SpanStream> VectorStream::slice(uint32_t offset,
                                                size_t size) const {
  if (offset > binary_.size() || (offset + size) > binary_.size()) {
    return nullptr;
  }
  const uint8_t* start = binary_.data() + offset;
  return std::make_unique<SpanStream>(start, size);
}


std::unique_ptr<SpanStream> VectorStream::slice(uint32_t offset) const {
  return slice(offset, binary_.size() - offset);
}

}
