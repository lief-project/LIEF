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

Relocation::~Relocation(void) = default;

Relocation::Relocation(void) :
  LIEF::Relocation{},
  symbol_{nullptr},
  type_{0},
  architecture_{CPU_TYPES::CPU_TYPE_ANY},
  section_{nullptr},
  segment_{nullptr}
{}


Relocation::Relocation(uint64_t address, uint8_t type) :
  Relocation{}
{
  this->address_ = address;
  this->type_    = type;
}


//Relocation& Relocation::operator=(const Relocation& other) {
//  return *other.clone();
//}

Relocation::Relocation(const Relocation& other) :
  LIEF::Relocation{other},
  symbol_{nullptr},
  type_{other.type_},
  architecture_{other.architecture_},
  section_{nullptr},
  segment_{nullptr}
{}

void Relocation::swap(Relocation& other) {
  LIEF::Relocation::swap(other);

  std::swap(this->symbol_,       other.symbol_);
  std::swap(this->type_,         other.type_);
  std::swap(this->architecture_, other.architecture_);
  std::swap(this->section_,      other.section_);
  std::swap(this->segment_,      other.segment_);
}

uint8_t Relocation::type(void) const {
  return this->type_;
}

CPU_TYPES Relocation::architecture(void) const {
  return this->architecture_;
}

bool Relocation::has_symbol(void) const {
  return (this->symbol_ != nullptr);
}

Symbol& Relocation::symbol(void) {
  return const_cast<Symbol&>(static_cast<const Relocation*>(this)->symbol());
}

const Symbol& Relocation::symbol(void) const {
  if (not this->has_symbol()) {
    throw not_found("No symbol associated with this relocation");
  }
  return *this->symbol_;
}


// Section
// =======
bool Relocation::has_section(void) const {
  return (this->section_ != nullptr);
}

Section& Relocation::section(void) {
  return const_cast<Section&>(static_cast<const Relocation*>(this)->section());
}

const Section& Relocation::section(void) const {
  if (not this->has_section()) {
    throw not_found("No section associated with this relocation");
  }
  return *this->section_;
}


// Segment
// =======
bool Relocation::has_segment(void) const {
  return (this->segment_ != nullptr);
}

SegmentCommand& Relocation::segment(void) {
  return const_cast<SegmentCommand&>(static_cast<const Relocation*>(this)->segment());
}

const SegmentCommand& Relocation::segment(void) const {
  if (not this->has_segment()) {
    throw not_found("No segment associated with this relocation");
  }
  return *this->segment_;
}

void Relocation::type(uint8_t type) {
  this->type_ = type;
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Relocation::operator==(const Relocation& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return not (*this == rhs);
}


std::ostream& Relocation::print(std::ostream& os) const {
  os << std::hex;
  os << std::left;

  std::string symbol_name = "";
  if (this->has_symbol()) {
    symbol_name = this->symbol().name();
  }

  std::string section_name = "";
  if (this->has_section()) {
    section_name = this->section().name();
  }

  std::string segment_name = "";
  if (this->has_segment()) {
    segment_name = this->segment().name();
  }

  std::string segment_section_name = "";
  if (section_name.size() > 0 and segment_name.size() > 0) {
    segment_section_name = segment_name + "." + section_name;
  }

  std::string relocation_type = "";
  if (this->origin() == RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE) {
    switch (this->architecture()) {
      case CPU_TYPES::CPU_TYPE_X86:
        {
          relocation_type = to_string(static_cast<X86_RELOCATION>(this->type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_X86_64:
        {
          relocation_type = to_string(static_cast<X86_64_RELOCATION>(this->type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_ARM:
        {
          relocation_type = to_string(static_cast<ARM_RELOCATION>(this->type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_ARM64:
        {
          relocation_type = to_string(static_cast<ARM64_RELOCATION>(this->type()));
          break;
        }

      case CPU_TYPES::CPU_TYPE_POWERPC:
        {
          relocation_type = to_string(static_cast<PPC_RELOCATION>(this->type()));
          break;
        }

      default:
        {
          relocation_type = std::to_string(this->type());
        }
    }
  }

  if (this->origin() == RELOCATION_ORIGINS::ORIGIN_DYLDINFO) {
    relocation_type = to_string(static_cast<REBASE_TYPES>(this->type()));
  }


  os << std::setw(10) << this->address()
     << std::setw(20) << relocation_type
     << std::setw(4) << std::dec << static_cast<uint32_t>(this->size());

  os << std::setw(10) << to_string(this->origin());

  if (segment_section_name.size() > 0) {
      os << segment_section_name;
  } else {
    if (section_name.size() > 0) {
      os << section_name;
    }

    if (segment_name.size() > 0) {
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
