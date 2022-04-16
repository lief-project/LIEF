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
#include "logging.hpp"

#include "LIEF/BinaryStream/SpanStream.hpp"
namespace LIEF {

SpanStream::SpanStream(SpanStream&& other) = default;
SpanStream& SpanStream::operator=(SpanStream&& other) = default;

SpanStream::SpanStream(span<const uint8_t> data) :
  data_{data}
{
  stype_ = STREAM_TYPE::SPAN;
}


SpanStream::SpanStream(span<uint8_t> data) :
  SpanStream(span<const uint8_t>(data.data(), data.size()))
{}

SpanStream::SpanStream(const std::vector<uint8_t>& data) :
  data_{data}
{
  stype_ = STREAM_TYPE::SPAN;
}

result<SpanStream> SpanStream::from_vector(const std::vector<uint8_t>& data) {
  return SpanStream{data};
}

result<const void*> SpanStream::read_at(uint64_t offset, uint64_t size) const {
  const uint64_t stream_size = this->size();
  if (offset > stream_size || (offset + size) > stream_size) {
    size_t out_size = (offset + size) - stream_size;
    LIEF_DEBUG("Can't read #{:d} bytes at 0x{:04x} (0x{:x} bytes out of bound)", size, offset, out_size);
    return make_error_code(lief_errors::read_error);
  }
  return data_.data() + offset;
}

result<SpanStream> SpanStream::slice(size_t offset, size_t size) const {
  if (offset > data_.size() || (offset + size) > data_.size()) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  return data_.subspan(offset, size);
}

result<SpanStream> SpanStream::slice(size_t offset) const {
  if (offset > data_.size()) {
    return make_error_code(lief_errors::read_out_of_bound);
  }
  return data_.subspan(offset, data_.size() - offset);
}


std::vector<uint8_t> SpanStream::content() const {
  return {std::begin(data_), std::end(data_)};
}


bool SpanStream::classof(const BinaryStream& stream) {
  return stream.type() == STREAM_TYPE::SPAN;
}

SpanStream::~SpanStream() = default;
}

