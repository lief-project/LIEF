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
#include <iostream>
#include <iomanip>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"


namespace LIEF {
namespace PE {

DataDirectory::~DataDirectory() = default;

DataDirectory::DataDirectory() = default;


DataDirectory::DataDirectory(DATA_DIRECTORY type) :
  type_{type}
{}

DataDirectory::DataDirectory(const details::pe_data_directory& header, DATA_DIRECTORY type) :
  rva_{header.RelativeVirtualAddress},
  size_{header.Size},
  type_{type}
{}

DataDirectory::DataDirectory(const DataDirectory& other) = default;

DataDirectory& DataDirectory::operator=(DataDirectory other) {
  swap(other);
  return *this;
}

void DataDirectory::swap(DataDirectory& other) {
  std::swap(rva_,     other.rva_);
  std::swap(size_,    other.size_);
  std::swap(type_,    other.type_);
  std::swap(section_, other.section_);
}

uint32_t DataDirectory::RVA() const {
  return rva_;
}


uint32_t DataDirectory::size() const {
  return size_;
}


bool DataDirectory::has_section() const {
  return section_ != nullptr;
}


const Section* DataDirectory::section() const {
  return section_;
}

Section* DataDirectory::section() {
  return const_cast<Section*>(static_cast<const DataDirectory*>(this)->section());
}

DATA_DIRECTORY DataDirectory::type() const {
  return type_;
}

void DataDirectory::RVA(uint32_t rva) {
  rva_ = rva;
}


void DataDirectory::size(uint32_t size) {
  size_ = size;
}

void DataDirectory::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}



bool DataDirectory::operator==(const DataDirectory& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DataDirectory::operator!=(const DataDirectory& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const DataDirectory& entry) {
  os << std::hex;
  os << "Data directory \"" << to_string(entry.type()) << "\"" << std::endl;
  os << std::setw(10) << std::left << std::setfill(' ') << "RVA: 0x"  << entry.RVA()  << std::endl;
  os << std::setw(10) << std::left << std::setfill(' ') << "Size: 0x" << entry.size() << std::endl;
  if (entry.has_section()) {
    os << std::setw(10) << std::left << std::setfill(' ') << "Section: " << entry.section()->name() << std::endl;
  }

  return os;

}
}
}
