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

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/TLS.hpp"

namespace LIEF {
namespace PE {

TLS::~TLS(void) = default;

TLS::TLS(void) :
  Object{},
  callbacks_{},
  VAOfRawData_{std::make_pair<uint64_t>(0, 0)},
  addressof_index_{0},
  addressof_callbacks_{0},
  sizeof_zero_fill_{0},
  characteristics_{0},
  directory_{nullptr},
  section_{nullptr},
  data_template_{}
{}

TLS::TLS(const TLS& copy) :
  Object{copy},
  callbacks_{copy.callbacks_},
  VAOfRawData_{copy.VAOfRawData_},
  addressof_index_{copy.addressof_index_},
  addressof_callbacks_{copy.addressof_callbacks_},
  sizeof_zero_fill_{copy.sizeof_zero_fill_},
  characteristics_{copy.characteristics_},
  directory_{nullptr},
  section_{nullptr},
  data_template_{copy.data_template_}
{}

TLS& TLS::operator=(TLS copy) {
  this->swap(copy);
  return *this;
}

void TLS::swap(TLS& other) {
  std::swap(this->callbacks_,           other.callbacks_);
  std::swap(this->VAOfRawData_,         other.VAOfRawData_);
  std::swap(this->addressof_index_,     other.addressof_index_);
  std::swap(this->addressof_callbacks_, other.addressof_callbacks_);
  std::swap(this->sizeof_zero_fill_,    other.sizeof_zero_fill_);
  std::swap(this->characteristics_,     other.characteristics_);
  std::swap(this->directory_,           other.directory_);
  std::swap(this->section_,             other.section_);
  std::swap(this->data_template_,       other.data_template_);
}

TLS::TLS(const pe32_tls *header) :
  callbacks_{},
  VAOfRawData_{header->RawDataStartVA, header->RawDataEndVA},
  addressof_index_{header->AddressOfIndex},
  addressof_callbacks_{header->AddressOfCallback},
  sizeof_zero_fill_{header->SizeOfZeroFill},
  characteristics_{header->Characteristics},
  directory_{nullptr},
  section_{nullptr},
  data_template_{}
{}


TLS::TLS(const pe64_tls *header) :
  callbacks_{},
  VAOfRawData_{header->RawDataStartVA, header->RawDataEndVA},
  addressof_index_{header->AddressOfIndex},
  addressof_callbacks_{header->AddressOfCallback},
  sizeof_zero_fill_{header->SizeOfZeroFill},
  characteristics_{header->Characteristics},
  directory_{nullptr},
  section_{nullptr},
  data_template_{}
{}

const std::vector<uint64_t>& TLS::callbacks(void) const {
  return this->callbacks_;
}


std::pair<uint64_t, uint64_t> TLS::addressof_raw_data(void) const {
  return this->VAOfRawData_;
}

uint64_t TLS::addressof_index(void) const {
  return this->addressof_index_;
}


uint64_t TLS::addressof_callbacks(void) const {
  return this->addressof_callbacks_;
}


uint32_t TLS::sizeof_zero_fill(void) const {
  return this->sizeof_zero_fill_;
}


uint32_t TLS::characteristics(void) const {
  return this->characteristics_;
}


bool TLS::has_data_directory(void) const {
  return this->directory_ != nullptr;
}

const DataDirectory& TLS::directory(void) const {
  if (this->directory_ != nullptr) {
    return *(this->directory_);
  } else {
    throw not_found("There is no directory associated with TLS");
  }
}

DataDirectory& TLS::directory(void) {
  return const_cast<DataDirectory&>(static_cast<const TLS*>(this)->directory());
}


bool TLS::has_section(void) const {
  return this->section_ != nullptr;
}


const Section& TLS::section(void) const {
  if (this->section_ != nullptr) {
    return *(this->section_);
  } else {
    throw not_found("There is no section associated with TLS");
  }
}

Section& TLS::section(void) {
  return const_cast<Section&>(static_cast<const TLS*>(this)->section());
}


const std::vector<uint8_t>& TLS::data_template(void) const {
  return this->data_template_;
}


void TLS::callbacks(const std::vector<uint64_t>& callbacks) {
  this->callbacks_ = callbacks;
}


void TLS::addressof_raw_data(std::pair<uint64_t, uint64_t> VAOfRawData) {
  this->VAOfRawData_ = VAOfRawData;
}


void TLS::addressof_index(uint64_t addressOfIndex) {
  this->addressof_index_ = addressOfIndex;
}


void TLS::addressof_callbacks(uint64_t addressOfCallbacks) {
  this->addressof_callbacks_ = addressOfCallbacks;
}


void TLS::sizeof_zero_fill(uint32_t sizeOfZeroFill) {
  this->sizeof_zero_fill_ = sizeOfZeroFill;
}


void TLS::characteristics(uint32_t characteristics) {
  this->characteristics_ = characteristics;
}


void TLS::data_template(const std::vector<uint8_t>& dataTemplate) {
  this->data_template_ = dataTemplate;
}


void TLS::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool TLS::operator==(const TLS& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool TLS::operator!=(const TLS& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const TLS& entry) {
  os << std::hex;
  os << std::setw(40) << std::left << std::setfill(' ') << "Address Of Index: "                     << entry.addressof_index()        << std::endl;
  os << std::setw(40) << std::left << std::setfill(' ') << "Address Of Callbacks: "                 << entry.addressof_callbacks()    << std::endl;

  for (uint64_t value : entry.callbacks()) {
    os << "\t - " << value << std::endl;
  }

  os << std::setw(40) << std::left << std::setfill(' ') << "Virtual Address of RawData (start): "   << entry.addressof_raw_data().first     << std::endl;
  os << std::setw(40) << std::left << std::setfill(' ') << "Virtual Address of RawData (end): "     << entry.addressof_raw_data().second    << std::endl;
  os << std::setw(40) << std::left << std::setfill(' ') << "Size Of Zero Fill: "                    << entry.sizeof_zero_fill()        << std::endl;

  if (entry.has_section()) {
    os << std::setw(40) << std::left << std::setfill(' ') << "Associated section: "                 << entry.section().name() << std::endl;
  }
  return os;
}

} // namespace PE
} // namespace LIEF

