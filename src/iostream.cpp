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
#include "LIEF/iostream.hpp"

namespace LIEF {

size_t vector_iostream::uleb128_size(uint64_t value) {
  size_t size = 0;
  do {
    value >>= 7;
    size += sizeof(int8_t);
  } while (value != 0);
  return size;
}

size_t vector_iostream::sleb128_size(int64_t value) {
  size_t size = 0;
  int sign = value >> (8 * sizeof(value) - 1);
  bool is_more = false;
  do {
    size_t byte = value & 0x7F;
    value >>= 7;
    is_more = value != sign || ((byte ^ sign) & 0x40) != 0;
    size += sizeof(int8_t);
  } while (is_more);
  return size;
}

vector_iostream& vector_iostream::put(uint8_t c) {
  size_t pos = 0;
  if (!checked_write_pos(1, pos)) {
    return *this;
  }

  const size_t end = pos + 1;
  if (raw_->size() < end) {
    raw_->resize(end);
  }
  (*raw_)[pos] = c;
  current_pos_ = (off_type)end;
  return *this;
}

vector_iostream& vector_iostream::write(const uint8_t* s, std::streamsize n) {
  if (n < 0) {
    return *this;
  }

  const auto count = (size_t)n;
  size_t pos = 0;
  if (!checked_write_pos(count, pos)) {
    return *this;
  }

  const size_t end = pos + count;
  if (raw_->size() < end) {
    raw_->resize(end);
  }
  std::copy(s, s + count, raw_->data() + pos);
  current_pos_ = (off_type)end;

  return *this;
}

vector_iostream& vector_iostream::write_uleb128(uint64_t value) {
  uint8_t byte = 0;
  do {
    byte = value & 0x7F;
    value &= ~0x7F;
    if (value != 0) {
      byte |= 0x80;
    }
    write<uint8_t>(byte);
    value = value >> 7;
  } while (byte >= 0x80);

  return *this;
}

vector_iostream& vector_iostream::write_sleb128(int64_t value) {

  bool is_neg = (value < 0);
  uint8_t byte = 0;
  bool more = false;
  do {
    byte = value & 0x7F;
    value = value >> 7;

    if (is_neg) {
      more = ((value != -1) || ((byte & 0x40) == 0));
    } else {
      more = ((value != 0) || ((byte & 0x40) != 0));
    }
    if (more) {
      byte |= 0x80;
    }
    write<uint8_t>(byte);
  } while (more);

  return *this;
}

vector_iostream& vector_iostream::seekp(off_type p, std::ios_base::seekdir dir) {
  switch (dir) {
    case std::ios_base::beg: return seekp((pos_type)p);
    case std::ios_base::end: return *this;
    case std::ios_base::cur:
    {
      const auto current = (off_type)current_pos_;
      if (current < 0 ||
          (p > 0 && current > std::numeric_limits<off_type>::max() - p) ||
          (p < 0 && p < -current))
      {
        return *this;
      }
      return seekp((pos_type)(current + p));
    }
    default: return *this;
  }

  return *this;
}

vector_iostream& vector_iostream::write(const std::u16string& s,
                                        bool with_null_char) {
  const size_t nullchar = with_null_char ? 1 : 0;
  if (s.size() > std::numeric_limits<size_t>::max() - nullchar) {
    return *this;
  }

  const size_t char_count = s.size() + nullchar;
  if (char_count > std::numeric_limits<size_t>::max() / sizeof(char16_t)) {
    return *this;
  }

  const size_t count = char_count * sizeof(char16_t);
  size_t pos = 0;
  if (!checked_write_pos(count, pos)) {
    return *this;
  }

  const size_t end = pos + count;
  if (raw_->size() < end) {
    raw_->resize(end);
  }

  std::copy(reinterpret_cast<const char16_t*>(s.data()),
            reinterpret_cast<const char16_t*>(s.data()) + s.size(),
            reinterpret_cast<char16_t*>(raw_->data() + pos));
  current_pos_ = (off_type)end;
  return *this;
}

vector_iostream& vector_iostream::align(size_t alignment, uint8_t fill) {
  if (raw_->size() % alignment == 0) {
    return *this;
  }

  while (raw_->size() % alignment != 0) {
    write<uint8_t>(fill);
  }

  return *this;
}
}
