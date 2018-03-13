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
#include <iomanip>

#include "LIEF/logging++.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/EnumToString.hpp"


namespace LIEF {
namespace PE {

RelocationEntry::RelocationEntry(const RelocationEntry& other) :
  LIEF::Relocation{other},
  position_{other.position_},
  type_{other.type_},
  relocation_{nullptr}
{}

RelocationEntry& RelocationEntry::operator=(RelocationEntry other) {
  this->swap(other);
  return *this;
}

RelocationEntry::~RelocationEntry(void) = default;

RelocationEntry::RelocationEntry(void) :
  LIEF::Relocation{},
  position_{0},
  type_{RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_ABSOLUTE},
  relocation_{nullptr}
{}

RelocationEntry::RelocationEntry(uint16_t data) :
  LIEF::Relocation{},
  position_{static_cast<uint16_t>(data & 0x0FFF)},
  type_{static_cast<RELOCATIONS_BASE_TYPES>(data >> 12)},
  relocation_{nullptr}
{}


RelocationEntry::RelocationEntry(uint16_t position, RELOCATIONS_BASE_TYPES type) :
  LIEF::Relocation{},
  position_{position},
  type_{type},
  relocation_{nullptr}
{}


void RelocationEntry::swap(RelocationEntry& other) {
  LIEF::Relocation::swap(other);
  std::swap(this->position_,   other.position_);
  std::swap(this->type_,       other.type_);
  std::swap(this->relocation_, other.relocation_);
}


uint16_t RelocationEntry::data(void) const {
  return (static_cast<uint8_t>(this->type_) << 12 | static_cast<uint16_t>(this->position_));
}


uint16_t RelocationEntry::position(void) const {
  return this->position_;
}


RELOCATIONS_BASE_TYPES RelocationEntry::type(void) const {
  return this->type_;
}

void RelocationEntry::data(uint16_t data) {
  this->position_ = static_cast<uint16_t>(data & 0x0FFF);
  this->type_     = static_cast<RELOCATIONS_BASE_TYPES>(data >> 12);
}

void RelocationEntry::position(uint16_t position) {
  this->position_ = position;
}


void RelocationEntry::type(RELOCATIONS_BASE_TYPES type) {
  this->type_ = type;
}



uint64_t RelocationEntry::address(void) const {
  if (this->relocation_ != nullptr) {
    return this->relocation_->virtual_address() + this->position();
  }

  return this->position();
}

void RelocationEntry::address(uint64_t address) {
  LOG(WARNING) << "Setting address of a PE relocation is not implemented!";
}

size_t RelocationEntry::size(void) const {
  switch (this->type()) {
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_LOW:
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_HIGH:
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_HIGHADJ:
      {
        return 16;
        break;
      }

    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_HIGHLOW: // Addr += delta
      {
        return 32;
        break;
      }

    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_DIR64: // Addr += delta
      {
        return 64;
        break;
      }
    case RELOCATIONS_BASE_TYPES::IMAGE_REL_BASED_ABSOLUTE:
    default:
      {
        return 0;
        break;
      }
  }
  return 0;
}
void RelocationEntry::size(size_t size) {
  LOG(WARNING) << "Setting size of a PE relocation is not implemented!";

}

void RelocationEntry::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool RelocationEntry::operator==(const RelocationEntry& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RelocationEntry::operator!=(const RelocationEntry& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const RelocationEntry& entry) {
  os << std::hex << std::left;
  os << std::setw(10) << to_string(entry.type());
  os << std::setw(6) << static_cast<uint32_t>(entry.position());

  return os;

}

}
}
