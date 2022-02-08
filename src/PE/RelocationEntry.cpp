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

#include "logging.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/EnumToString.hpp"


namespace LIEF {
namespace PE {

RelocationEntry::RelocationEntry(const RelocationEntry& other) :
  LIEF::Relocation{other},
  position_{other.position_},
  type_{other.type_}
{}

RelocationEntry& RelocationEntry::operator=(RelocationEntry other) {
  swap(other);
  return *this;
}

RelocationEntry::~RelocationEntry() = default;

RelocationEntry::RelocationEntry() :
  position_{0},
  type_{RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_ABSOLUTE}
{}

RelocationEntry::RelocationEntry(uint16_t data) :
  position_{static_cast<uint16_t>(data & 0x0FFF)},
  type_{static_cast<RELOCATIONS_BASE_TYPES>(data >> 12)}
{}


RelocationEntry::RelocationEntry(uint16_t position, RELOCATIONS_BASE_TYPES type) :
  position_{position},
  type_{type}
{}


void RelocationEntry::swap(RelocationEntry& other) {
  LIEF::Relocation::swap(other);
  std::swap(position_,   other.position_);
  std::swap(type_,       other.type_);
  std::swap(relocation_, other.relocation_);
}


uint16_t RelocationEntry::data() const {
  return (static_cast<uint8_t>(type_) << 12 | static_cast<uint16_t>(position_));
}


uint16_t RelocationEntry::position() const {
  return position_;
}


RELOCATIONS_BASE_TYPES RelocationEntry::type() const {
  return type_;
}

void RelocationEntry::data(uint16_t data) {
  position_ = static_cast<uint16_t>(data & 0x0FFF);
  type_     = static_cast<RELOCATIONS_BASE_TYPES>(data >> 12);
}

void RelocationEntry::position(uint16_t position) {
  position_ = position;
}


void RelocationEntry::type(RELOCATIONS_BASE_TYPES type) {
  type_ = type;
}



uint64_t RelocationEntry::address() const {
  if (relocation_ != nullptr) {
    return relocation_->virtual_address() + position();
  }

  return position();
}

void RelocationEntry::address(uint64_t /*address*/) {
  LIEF_WARN("Setting address of a PE relocation is not implemented!");
}

size_t RelocationEntry::size() const {
  switch (type()) {
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_LOW:
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_HIGH:
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_HIGHADJ:
      {
        return 16;
      }

    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_HIGHLOW: // Addr += delta
      {
        return 32;
      }

    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_DIR64: // Addr += delta
      {
        return 64;
      }
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_ABSOLUTE:
    default:
      {
        return 0;
      }
  }
  return 0;
}
void RelocationEntry::size(size_t /*size*/) {
  LIEF_WARN("Setting size of a PE relocation is not implemented!");

}

void RelocationEntry::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool RelocationEntry::operator==(const RelocationEntry& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RelocationEntry::operator!=(const RelocationEntry& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const RelocationEntry& entry) {
  os << std::hex << std::left;
  os << std::setw(10) << to_string(entry.type());
  os << std::setw(6) << static_cast<uint32_t>(entry.position());

  return os;

}

}
}
