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
#include <iomanip>

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/RichHeader.hpp"
#include "LIEF/iostream.hpp"
#include "LIEF/PE/EnumToString.hpp"


#include "logging.hpp"

#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"

#include "PE/Structures.hpp"
#include "hash_stream.hpp"

namespace LIEF {
namespace PE {

RichHeader::~RichHeader() = default;
RichHeader::RichHeader(const RichHeader&) = default;
RichHeader& RichHeader::operator=(const RichHeader&) = default;

RichHeader::RichHeader() = default;

uint32_t RichHeader::key() const {
  return key_;
}

RichHeader::it_entries RichHeader::entries() {
  return entries_;
}

RichHeader::it_const_entries RichHeader::entries() const {
  return entries_;
}

void RichHeader::key(uint32_t key) {
  key_ = key;
}

void RichHeader::add_entry(const RichEntry& entry) {
  entries_.push_back(entry);
}

void RichHeader::add_entry(uint16_t id, uint16_t build_id, uint32_t count) {
  entries_.emplace_back(id, build_id, count);
}

void RichHeader::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::vector<uint8_t> RichHeader::raw() const {
  return raw(0);
}

std::vector<uint8_t> RichHeader::raw(uint32_t xor_key) const {
  static constexpr uint32_t RICH_MAGIC = 0x68636952;
  vector_iostream wstream;

  wstream
    .write(details::DanS_Magic_number ^ xor_key)
    /*
     * The first chunk needs to be aligned on 64-bit and padded
     * with 0-xor. We can't use vector_iostream::align as it would not
     * be encoded.
     */
    .write<uint32_t>(0 ^ xor_key)
    .write<uint32_t>(0 ^ xor_key)
    .write<uint32_t>(0 ^ xor_key);

  for (auto it = entries_.crbegin(); it != entries_.crend(); ++it) {
    const RichEntry& entry = *it;
    const uint32_t value = (static_cast<uint32_t>(entry.id()) << 16) | entry.build_id();
    wstream
      .write(value ^ xor_key).write(entry.count() ^ xor_key);
  }

  wstream
    .write(RICH_MAGIC).write(xor_key);

  return wstream.raw();
}


std::vector<uint8_t> RichHeader::hash(ALGORITHMS algo) const {
  return hash(algo, 0);
}

std::vector<uint8_t> RichHeader::hash(ALGORITHMS algo, uint32_t xor_key) const {
  static const std::map<ALGORITHMS, hashstream::HASH> HMAP = {
    {ALGORITHMS::MD5,     hashstream::HASH::MD5},
    {ALGORITHMS::SHA_1,   hashstream::HASH::SHA1},
    {ALGORITHMS::SHA_256, hashstream::HASH::SHA256},
    {ALGORITHMS::SHA_384, hashstream::HASH::SHA384},
    {ALGORITHMS::SHA_512, hashstream::HASH::SHA512},
  };

  auto it_hash = HMAP.find(algo);
  if (it_hash == std::end(HMAP)) {
    LIEF_WARN("Unsupported hash algorithm: {}", to_string(algo));
    return {};
  }

  const hashstream::HASH hash_type = it_hash->second;
  hashstream hs(hash_type);
  const std::vector<uint8_t> clear_raw = raw(xor_key);
  hs.write(clear_raw.data(), clear_raw.size());
  return hs.raw();
}

bool RichHeader::operator==(const RichHeader& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RichHeader::operator!=(const RichHeader& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const RichHeader& rich_header) {
  os << "Key: " << std::hex << rich_header.key() << std::endl;
  for (const RichEntry& entry : rich_header.entries()) {
    os << "  - " << entry << std::endl;
  }
  return os;
}

}
}
