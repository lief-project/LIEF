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
#include "logging.hpp"

#include "LIEF/Visitor.hpp"

#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/Relocation.hpp"

#include "frozen.hpp"
#include "fmt_formatter.hpp"

FMT_FORMATTER(LIEF::PE::RelocationEntry::BASE_TYPES, LIEF::PE::to_string);

namespace LIEF {
namespace PE {

RelocationEntry::RelocationEntry(const RelocationEntry& other) :
  LIEF::Relocation{other},
  position_{other.position_},
  type_{other.type_},
  arch_{other.arch_},
  relocation_{nullptr}
{}

RelocationEntry::RelocationEntry(uint16_t data, Header::MACHINE_TYPES arch) :
  arch_(arch)
{
  this->data(data);
}

void RelocationEntry::swap(RelocationEntry& other) {
  LIEF::Relocation::swap(other);
  std::swap(position_,   other.position_);
  std::swap(type_,       other.type_);
  std::swap(relocation_, other.relocation_);
  std::swap(arch_,       other.arch_);
}


uint16_t RelocationEntry::data() const {
  auto raw_type = uint8_t(uint32_t(type_) & 0xFF);
  return (uint16_t(raw_type) << 12 | uint16_t(position_));
}

void RelocationEntry::data(uint16_t data) {
  position_ = static_cast<uint16_t>(data & 0x0FFF);
  auto raw_type = uint8_t(data >> 12);
  // TODO(romain): Support arch-dependent types (ARM_MOV32A, RISCV_LOW12I, ...)
  type_ = BASE_TYPES(raw_type);
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
    case BASE_TYPES::LOW:
    case BASE_TYPES::HIGH:
    case BASE_TYPES::HIGHADJ:
      {
        return 16;
      }

    case BASE_TYPES::HIGHLOW: // Addr += delta
      {
        return 32;
      }

    case BASE_TYPES::DIR64: // Addr += delta
      {
        return 64;
      }
    case BASE_TYPES::ABS:
    default:
      {
        return 0;
      }
  }
  return 0;
}

void RelocationEntry::size(size_t /*size*/) {
  LIEF_WARN("Setting size of a PE relocation is not supported!");
}

void RelocationEntry::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const RelocationEntry& entry) {
  os << fmt::format("{}: 0x{:04x}", entry.type(), entry.position());
  return os;
}

const char* to_string(RelocationEntry::BASE_TYPES type) {
  #define ENTRY(X) std::pair(RelocationEntry::BASE_TYPES::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNKNOWN),
    ENTRY(ABS),
    ENTRY(HIGH),
    ENTRY(LOW),
    ENTRY(HIGHLOW),
    ENTRY(HIGHADJ),
    ENTRY(MIPS_JMPADDR),
    ENTRY(ARM_MOV32A),
    ENTRY(ARM_MOV32),
    ENTRY(RISCV_HI20),
    ENTRY(SECTION),
    ENTRY(REL),
    ENTRY(ARM_MOV32T),
    ENTRY(THUMB_MOV32),
    ENTRY(RISCV_LOW12I),
    ENTRY(RISCV_LOW12S),
    ENTRY(MIPS_JMPADDR16),
    ENTRY(IA64_IMM64),
    ENTRY(DIR64),
    ENTRY(HIGH3ADJ),
  };
  #undef ENTRY

  if (auto it = enums2str.find(type); it != enums2str.end()) {
    return it->second;
  }

  return "UNKNOWN";
}


}
}
