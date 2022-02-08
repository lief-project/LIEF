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

#include "LIEF/exception.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/Section.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

TLS::~TLS() = default;
TLS::TLS() = default;

TLS::TLS(const TLS& copy) = default;

TLS& TLS::operator=(TLS copy) {
  swap(copy);
  return *this;
}

void TLS::swap(TLS& other) {
  std::swap(callbacks_,           other.callbacks_);
  std::swap(VAOfRawData_,         other.VAOfRawData_);
  std::swap(addressof_index_,     other.addressof_index_);
  std::swap(addressof_callbacks_, other.addressof_callbacks_);
  std::swap(sizeof_zero_fill_,    other.sizeof_zero_fill_);
  std::swap(characteristics_,     other.characteristics_);
  std::swap(directory_,           other.directory_);
  std::swap(section_,             other.section_);
  std::swap(data_template_,       other.data_template_);
}

TLS::TLS(const details::pe32_tls& header) :
  VAOfRawData_{header.RawDataStartVA, header.RawDataEndVA},
  addressof_index_{header.AddressOfIndex},
  addressof_callbacks_{header.AddressOfCallback},
  sizeof_zero_fill_{header.SizeOfZeroFill},
  characteristics_{header.Characteristics}
{}


TLS::TLS(const details::pe64_tls& header) :
  VAOfRawData_{header.RawDataStartVA, header.RawDataEndVA},
  addressof_index_{header.AddressOfIndex},
  addressof_callbacks_{header.AddressOfCallback},
  sizeof_zero_fill_{header.SizeOfZeroFill},
  characteristics_{header.Characteristics}
{}

const std::vector<uint64_t>& TLS::callbacks() const {
  return callbacks_;
}


std::pair<uint64_t, uint64_t> TLS::addressof_raw_data() const {
  return VAOfRawData_;
}

uint64_t TLS::addressof_index() const {
  return addressof_index_;
}


uint64_t TLS::addressof_callbacks() const {
  return addressof_callbacks_;
}


uint32_t TLS::sizeof_zero_fill() const {
  return sizeof_zero_fill_;
}


uint32_t TLS::characteristics() const {
  return characteristics_;
}


bool TLS::has_data_directory() const {
  return directory_ != nullptr;
}

const DataDirectory* TLS::directory() const {
  return directory_;
}

DataDirectory* TLS::directory() {
  return const_cast<DataDirectory*>(static_cast<const TLS*>(this)->directory());
}


bool TLS::has_section() const {
  return section_ != nullptr;
}


const Section* TLS::section() const {
  return section_;
}

Section* TLS::section() {
  return const_cast<Section*>(static_cast<const TLS*>(this)->section());
}


const std::vector<uint8_t>& TLS::data_template() const {
  return data_template_;
}


void TLS::callbacks(const std::vector<uint64_t>& callbacks) {
  callbacks_ = callbacks;
}


void TLS::addressof_raw_data(std::pair<uint64_t, uint64_t> VAOfRawData) {
  VAOfRawData_ = VAOfRawData;
}


void TLS::addressof_index(uint64_t addressOfIndex) {
  addressof_index_ = addressOfIndex;
}


void TLS::addressof_callbacks(uint64_t addressOfCallbacks) {
  addressof_callbacks_ = addressOfCallbacks;
}


void TLS::sizeof_zero_fill(uint32_t sizeOfZeroFill) {
  sizeof_zero_fill_ = sizeOfZeroFill;
}


void TLS::characteristics(uint32_t characteristics) {
  characteristics_ = characteristics;
}


void TLS::data_template(const std::vector<uint8_t>& dataTemplate) {
  data_template_ = dataTemplate;
}


void TLS::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool TLS::operator==(const TLS& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool TLS::operator!=(const TLS& rhs) const {
  return !(*this == rhs);
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
    os << std::setw(40) << std::left << std::setfill(' ') << "Associated section: "                 << entry.section()->name() << std::endl;
  }
  return os;
}

} // namespace PE
} // namespace LIEF

