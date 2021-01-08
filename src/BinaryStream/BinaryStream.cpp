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
#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/DWARF/enums.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/third-party/utfcpp/utf8/checked.h"

#include <iomanip>
#include <sstream>
#include <algorithm>
#include <iostream>

namespace LIEF {
BinaryStream::~BinaryStream(void) = default;
BinaryStream::BinaryStream(void) = default;

void BinaryStream::setpos(size_t pos) const {
  this->pos_ = pos;
}

void BinaryStream::increment_pos(size_t value) const {
  this->pos_ += value;
}


BinaryStream::operator bool() const {
  return this->pos_ < this->size();
}

size_t BinaryStream::pos(void) const {
  return this->pos_;
}


int64_t BinaryStream::read_dwarf_encoded(uint8_t encoding) {
  LIEF::DWARF::EH_ENCODING encodevalue =  static_cast<LIEF::DWARF::EH_ENCODING>(encoding & 0x0F);

  switch (encodevalue) {
    case LIEF::DWARF::EH_ENCODING::ULEB128:
      {
        return this->read_uleb128();
      }

    case LIEF::DWARF::EH_ENCODING::SDATA2:
    case LIEF::DWARF::EH_ENCODING::UDATA2:
      {
        return this->read<int16_t>();
      }

    case LIEF::DWARF::EH_ENCODING::SDATA4:
    case LIEF::DWARF::EH_ENCODING::UDATA4:
      {
        return this->read<int32_t>();
      }

    case LIEF::DWARF::EH_ENCODING::SDATA8:
    case LIEF::DWARF::EH_ENCODING::UDATA8:
      {
        return this->read<int64_t>();
      }

    case LIEF::DWARF::EH_ENCODING::SLEB128:
      {
        return this->read_sleb128();
      }

    default:
      {
        return 0;
      }

  }

}

uint64_t BinaryStream::read_uleb128(void) const {
  uint64_t value = 0;
  unsigned shift = 0;
  uint8_t byte_read;
  do {
    byte_read = this->read<uint8_t>();
    value += static_cast<uint64_t>(byte_read & 0x7f) << shift;
    shift += 7;
  } while (byte_read >= 128);

  return value;
}

uint64_t BinaryStream::read_sleb128(void) const {
  int64_t  value = 0;
  unsigned shift = 0;
  uint8_t byte_read;
  do {
    byte_read = this->read<uint8_t>();
    value += static_cast<int64_t>(byte_read & 0x7f) << shift;
    shift += 7;
  } while (byte_read >= 128);


  // Sign extend
  if ((byte_read & 0x40) != 0) {
    value |= static_cast<int64_t>(-1) << shift;
  }

  return value;
}

std::string BinaryStream::read_string(size_t maxsize) const {
  std::string str = this->peek_string(maxsize);
  this->increment_pos(str.size() + 1); // +1 for'\0'
  return str;
}

std::string BinaryStream::peek_string(size_t maxsize) const {
  std::string result;
  result.reserve(10);
  char c = '\0';
  size_t off = this->pos();

  if (not this->can_read<char>()) {
    return result.c_str();
  }

  size_t count = 0;
  do {
    c = this->peek<char>(off);
    off += sizeof(char);
    result.push_back(c);
    ++count;
  } while (count < maxsize and c != '\0' and this->pos() < this->size());
  result.back() = '\0';
  return result.c_str();

}

std::string BinaryStream::peek_string_at(size_t offset, size_t maxsize) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  std::string tmp = this->peek_string(maxsize);
  this->setpos(saved_offset);
  return tmp;
}

std::u16string BinaryStream::read_u16string(void) const {
  std::u16string str = this->peek_u16string();
  this->increment_pos((str.size() + 1) * sizeof(uint16_t)); // +1 for'\0'
  return str;
}

std::u16string BinaryStream::peek_u16string(void) const {
  std::u16string result;
  result.reserve(10);
  char16_t c = '\0';
  size_t off = this->pos();

  if (not this->can_read<char16_t>()) {
    return result;
  }

  size_t count = 0;
  do {
    c = this->peek_conv<char16_t>(off);
    off += sizeof(char16_t);
    result.push_back(c);
    ++count;
  } while (c != 0 and this->pos() < this->size());
  result.back() = '\0';
  return result.c_str();
}


std::u16string BinaryStream::read_u16string(size_t length) const {
  std::u16string str = this->peek_u16string(length);
  this->increment_pos(length * sizeof(uint16_t)); // +1 for'\0'
  return str;
}

std::u16string BinaryStream::peek_u16string(size_t length) const {
  if (length == static_cast<size_t>(-1u)) {
    return this->peek_u16string();
  }
  std::unique_ptr<char16_t[]> raw = this->peek_conv_array<char16_t>(this->pos(), length, /* check */false);
  if (raw == nullptr) {
    return {};
  }
  return {raw.get(), length};
}

std::u16string BinaryStream::peek_u16string_at(size_t offset, size_t length) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  std::u16string tmp = this->peek_u16string(length);
  this->setpos(saved_offset);
  return tmp;
}


size_t BinaryStream::align(size_t align_on) const {
  if (align_on == 0 or (this->pos() % align_on) == 0) {
    return 0;
  }
  size_t padding = align_on - (this->pos() % align_on);
  this->increment_pos(padding);
  return padding;
}


std::string BinaryStream::read_mutf8(size_t maxsize) const {
  std::u32string u32str;

  for (size_t i = 0; i < maxsize; ++i) {
    uint8_t a = this->read<char>();

    if (static_cast<uint8_t>(a) < 0x80) {
      if (a == 0) {
        break;
      }
      u32str.push_back(a);
    } else if ((a & 0xe0) == 0xc0) {

      uint8_t b = this->read<int8_t>() & 0xFF;

      if ((b & 0xC0) != 0x80) {
        break;
      }
      u32str.push_back(static_cast<char32_t>((((a & 0x1F) << 6) | (b & 0x3F))));
    } else if ((a & 0xf0) == 0xe0) {
        uint8_t b = this->read<uint8_t>() & 0xFF;
        uint8_t c = this->read<uint8_t>() & 0xFF;

        if (((b & 0xC0) != 0x80) or ((c & 0xC0) != 0x80)) {
          break;
        }
        u32str.push_back(static_cast<char32_t>(((a & 0x1F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F)));
    } else {
      break;
    }
  }

  std::string u8str;

  std::replace_if(
      std::begin(u32str),
      std::end(u32str),
      [] (const char32_t c) {
        return not utf8::internal::is_code_point_valid(c);
      }, '.');

  utf8::utf32to8(std::begin(u32str), std::end(u32str), std::back_inserter(u8str));

  std::string u8str_clean;
  for (size_t i = 0; i < u8str.size(); ++i) {
    if (u8str[i] != -1) {
      u8str_clean.push_back(u8str[i]);
    } else {
      std::stringstream ss;
      ss << std::hex << "\\x" << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(u8str[i] & 0xFF);
      u8str_clean += ss.str();
    }
  }
  return u8str_clean;
}

void BinaryStream::set_endian_swap(bool swap) {
  this->endian_swap_ = swap;
}
}

