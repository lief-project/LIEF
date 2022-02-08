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
#include <sstream>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/CodeIntegrity.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

CodeIntegrity::~CodeIntegrity() = default;
CodeIntegrity& CodeIntegrity::operator=(const CodeIntegrity&) = default;
CodeIntegrity::CodeIntegrity(const CodeIntegrity&) = default;

CodeIntegrity::CodeIntegrity() :
  flags_{0},
  catalog_{0},
  catalog_offset_{0},
  reserved_{0}
{}


CodeIntegrity::CodeIntegrity(const details::pe_code_integrity& header) :
  flags_{header.Flags},
  catalog_{header.Catalog},
  catalog_offset_{header.CatalogOffset},
  reserved_{header.Reserved}
{}


uint16_t CodeIntegrity::flags() const {
  return flags_;
}
uint16_t CodeIntegrity::catalog() const {
  return catalog_;
}

uint32_t CodeIntegrity::catalog_offset() const {
  return catalog_offset_;
}

uint32_t CodeIntegrity::reserved() const {
  return reserved_;
}


void CodeIntegrity::flags(uint16_t flags) {
  flags_ = flags;
}

void CodeIntegrity::catalog(uint16_t catalog) {
  catalog_ = catalog;
}

void CodeIntegrity::catalog_offset(uint32_t catalog_offset) {
  catalog_offset_ = catalog_offset;
}

void CodeIntegrity::reserved(uint32_t reserved) {
  reserved_ = reserved;
}

void CodeIntegrity::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool CodeIntegrity::operator==(const CodeIntegrity& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CodeIntegrity::operator!=(const CodeIntegrity& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const CodeIntegrity& entry) {
  os << std::hex << std::left << std::showbase;
  os << std::setw(CodeIntegrity::PRINT_WIDTH) << std::setfill(' ') << "Flags:"          << std::hex << entry.flags()          << std::endl;
  os << std::setw(CodeIntegrity::PRINT_WIDTH) << std::setfill(' ') << "Catalog:"        << std::hex << entry.catalog()        << std::endl;
  os << std::setw(CodeIntegrity::PRINT_WIDTH) << std::setfill(' ') << "Catalog offset:" << std::hex << entry.catalog_offset() << std::endl;
  os << std::setw(CodeIntegrity::PRINT_WIDTH) << std::setfill(' ') << "Reserved:"       << std::hex << entry.reserved()       << std::endl;
  return os;

}

}
}
