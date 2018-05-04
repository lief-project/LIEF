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

#include "LIEF/OAT/DexFile.hpp"
#include "LIEF/OAT/hash.hpp"

namespace LIEF {
namespace OAT {

DexFile::DexFile(const DexFile&) = default;
DexFile& DexFile::operator=(const DexFile&) = default;

DexFile::DexFile(void) :
  location_{},
  checksum_{-1u},
  dex_offset_{0},
  dex_file_{nullptr},
  classes_offsets_{},
  lookup_table_offset_{0},
  method_bss_mapping_offset_{0},
  dex_sections_layout_offset_{0}
{}


const std::string& DexFile::location(void) const {
  return this->location_;
}

uint32_t DexFile::checksum(void) const {
  return this->checksum_;
}

uint32_t DexFile::dex_offset(void) const {
  return this->dex_offset_;
}

bool DexFile::has_dex_file(void) const {
  return this->dex_file_ != nullptr;
}

const DEX::File& DexFile::dex_file(void) const {
  if (not this->has_dex_file()) {
    throw not_found("Can't find the dex file associated with this OAT dex file");
  }
  return *this->dex_file_;
}



void DexFile::location(const std::string& location) {
  this->location_ = location;
}

void DexFile::checksum(uint32_t checksum) {
  this->checksum_ = checksum;
}

void DexFile::dex_offset(uint32_t dex_offset) {
  this->dex_offset_ = dex_offset;
}

const std::vector<uint32_t>& DexFile::classes_offsets(void) const {
  return this->classes_offsets_;
}


// Android 7.X.X and Android 8.0.0
// ===============================
uint32_t DexFile::lookup_table_offset(void) const {
  return this->lookup_table_offset_;
}

void DexFile::lookup_table_offset(uint32_t offset) {
  this->lookup_table_offset_ = offset;
}
// ===============================

DEX::File& DexFile::dex_file(void) {
  return const_cast<DEX::File&>(static_cast<const DexFile*>(this)->dex_file());
}

void DexFile::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool DexFile::operator==(const DexFile& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DexFile::operator!=(const DexFile& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const DexFile& dex_file) {
  os << dex_file.location() << " - " << std::hex << std::showbase << "(Checksum: " << dex_file.checksum() << ")";
  return os;
}

DexFile::~DexFile(void) = default;



}
}
