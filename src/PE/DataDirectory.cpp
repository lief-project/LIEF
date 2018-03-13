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
#include <iostream>
#include <iomanip>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/EnumToString.hpp"


namespace LIEF {
namespace PE {

DataDirectory::~DataDirectory(void) = default;

DataDirectory::DataDirectory(void) :
  rva_{0},
  size_{0},
  type_{},
  section_{nullptr}
{}

DataDirectory::DataDirectory(DATA_DIRECTORY type) :
  rva_{0},
  size_{0},
  type_{type},
  section_{nullptr}
{}

DataDirectory::DataDirectory(const pe_data_directory *header, DATA_DIRECTORY type) :
  rva_{header->RelativeVirtualAddress},
  size_{header->Size},
  type_{type},
  section_{nullptr}
{}

DataDirectory::DataDirectory(const DataDirectory& other) :
  Object{other},
  rva_{other.rva_},
  size_{other.size_},
  type_{other.type_},
  section_{nullptr}
{}

DataDirectory& DataDirectory::operator=(DataDirectory other) {
  this->swap(other);
  return *this;
}

void DataDirectory::swap(DataDirectory& other) {
  std::swap(this->rva_,     other.rva_);
  std::swap(this->size_,    other.size_);
  std::swap(this->type_,    other.type_);
  std::swap(this->section_, other.section_);
}



uint32_t DataDirectory::RVA(void) const {
  return this->rva_;
}


uint32_t DataDirectory::size(void) const {
  return this->size_;
}


bool DataDirectory::has_section(void) const {
  return this->section_ != nullptr;
}


const Section& DataDirectory::section(void) const {
  if (this->section_ != nullptr) {
    return *this->section_;
  } else {
    throw not_found("No section associated with the data directory '" +
        std::string{to_string(this->type())} + "'");
  }
}

Section& DataDirectory::section(void) {
  return const_cast<Section&>(static_cast<const DataDirectory*>(this)->section());
}

DATA_DIRECTORY DataDirectory::type(void) const {
  return this->type_;
}

void DataDirectory::RVA(uint32_t rva) {
  this->rva_ = rva;
}


void DataDirectory::size(uint32_t size) {
  this->size_ = size;
}

void DataDirectory::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}



bool DataDirectory::operator==(const DataDirectory& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DataDirectory::operator!=(const DataDirectory& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const DataDirectory& entry) {
  os << std::hex;
  os << "Data directory \"" << to_string(entry.type()) << "\"" << std::endl;
  os << std::setw(10) << std::left << std::setfill(' ') << "RVA: "  << entry.RVA()  << std::endl;
  os << std::setw(10) << std::left << std::setfill(' ') << "Size: " << entry.size() << std::endl;
  if (entry.has_section()) {
    os << std::setw(10) << std::left << std::setfill(' ') << "Section: " << entry.section().name() << std::endl;
  }

  return os;

}
}
}
