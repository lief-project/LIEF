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
#include <numeric>
#include <iomanip>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

Relocation::~Relocation() = default;
Relocation::Relocation() = default;

Relocation::Relocation(const Relocation& other) :
  LIEF::Relocation{other},
  type_{other.type_},
  architecture_{other.architecture_}
{}

Relocation::Relocation(uint64_t address, uint8_t type) {
  address_ = address;
  type_    = type;
}


Relocation& Relocation::operator=(const Relocation& other) {
  if (&other != this) {
    /* Do not copy pointer as they could be not bind to the same Binary */
    address_      = other.address_;
    size_         = other.size_;
    type_         = other.type_;
    architecture_ = other.architecture_;
  }
  return *this;
}
void Relocation::swap(Relocation& other) {
  LIEF::Relocation::swap(other);

  std::swap(symbol_,       other.symbol_);
  std::swap(type_,         other.type_);
  std::swap(architecture_, other.architecture_);
  std::swap(section_,      other.section_);
  std::swap(segment_,      other.segment_);
}

uint8_t Relocation::type() const {
  return type_;
}

CPU_TYPES Relocation::architecture() const {
  return architecture_;
}

bool Relocation::has_symbol() const {
  return symbol_ != nullptr;
}

Symbol* Relocation::symbol() {
  return const_cast<Symbol*>(static_cast<const Relocation*>(this)->symbol());
}

const Symbol* Relocation::symbol() const {
  return symbol_;
}


// Section
// =======
bool Relocation::has_section() const {
  return section_ != nullptr;
}

Section* Relocation::section() {
  return const_cast<Section*>(static_cast<const Relocation*>(this)->section());
}

const Section* Relocation::section() const {
  return section_;
}


bool Relocation::has_segment() const {
  return segment_ != nullptr;
}

SegmentCommand* Relocation::segment() {
  return const_cast<SegmentCommand*>(static_cast<const Relocation*>(this)->segment());
}

const SegmentCommand* Relocation::segment() const {
  return segment_;
}

void Relocation::type(uint8_t type) {
  type_ = type;
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Relocation::operator==(const Relocation& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return !(*this == rhs);
}


std::ostream& Relocation::print(std::ostream& os) const {
  os << std::hex;
  os << std::left;

  std::string symbol_name;
  if (has_symbol()) {
    symbol_name = symbol()->name();
  }

  std::string section_name;
  if (has_section()) {
    section_name = section()->name();
  }

  std::string segment_name;
  if (has_segment()) {
    segment_name = segment()->name();
  }

  std::string segment_section_name;
  if (!section_name.empty() && !segment_name.empty()) {
    segment_section_name = segment_name + "." + section_name;
  }
  else if (!segment_name.empty()) {
    segment_section_name = segment_name;
  }
  else if (!section_name.empty()) {
    segment_section_name = section_name;
  }

  std::string relocation_type;
  if (origin() == RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE) {
    switch (architecture()) {
      case CPU_TYPES::CPU_TYPE_X86:
        {
          relocation_type = to_string(static_cast<X86_RELOCATION>(type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_X86_64:
        {
          relocation_type = to_string(static_cast<X86_64_RELOCATION>(type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_ARM:
        {
          relocation_type = to_string(static_cast<ARM_RELOCATION>(type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_ARM64:
        {
          relocation_type = to_string(static_cast<ARM64_RELOCATION>(type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_POWERPC:
        {
          relocation_type = to_string(static_cast<PPC_RELOCATION>(type()));
          break;
        }

      default:
        {
          relocation_type = std::to_string(type());
        }
    }
  }

  if (origin() == RELOCATION_ORIGINS::ORIGIN_DYLDINFO) {
    relocation_type = to_string(static_cast<REBASE_TYPES>(type()));
  }


  os << std::setw(10) << address()
     << std::setw(20) << relocation_type
     << std::setw(4) << std::dec << static_cast<uint32_t>(size());

  os << std::setw(10) << to_string(origin());

  if (!segment_section_name.empty()) {
      os << segment_section_name;
  } else {
    if (!section_name.empty()) {
      os << section_name;
    }

    if (!segment_name.empty()) {
      os << section_name;
    }
  }

  os << " ";
  os << std::setw(10) << symbol_name;

  return os;
}


std::ostream& operator<<(std::ostream& os, const Relocation& reloc) {
  return reloc.print(os);
}


}
}
