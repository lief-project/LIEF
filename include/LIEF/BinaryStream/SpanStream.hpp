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
#ifndef LIEF_SPAN_STREAM_H
#define LIEF_SPAN_STREAM_H

#include <string>

#include "LIEF/errors.hpp"
#include "LIEF/span.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"

namespace LIEF {
class SpanStream : public BinaryStream {
  public:
  static result<SpanStream> from_vector(const std::vector<uint8_t>& data);
  SpanStream(span<const uint8_t> data);
  SpanStream(span<uint8_t> data);
  SpanStream(const std::vector<uint8_t>& data);
  SpanStream() = delete;

  SpanStream(const SpanStream&) = delete;
  SpanStream& operator=(const SpanStream&) = delete;

  SpanStream(SpanStream&& other);
  SpanStream& operator=(SpanStream&& other);

  inline uint64_t size() const override {
    return data_.size();
  }

  std::vector<uint8_t> content() const;

  result<SpanStream> slice(size_t offset, size_t size) const;
  result<SpanStream> slice(size_t offset) const;

  static bool classof(const BinaryStream& stream);
  ~SpanStream() override;

  protected:
  result<const void*> read_at(uint64_t offset, uint64_t size) const override;
  span<const uint8_t> data_;
};
}

#endif
