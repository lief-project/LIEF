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

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Debug.hpp"

namespace LIEF {
namespace PE {

Debug::Debug(const Debug& copy) :
  Object{copy},
  characteristics_{copy.characteristics_},
  timestamp_{copy.timestamp_},
  majorversion_{copy.majorversion_},
  minorversion_{copy.minorversion_},
  type_{copy.type_},
  sizeof_data_{copy.sizeof_data_},
  addressof_rawdata_{copy.addressof_rawdata_},
  pointerto_rawdata_{copy.pointerto_rawdata_},
  code_view_{nullptr}
{
  if (copy.has_code_view()) {
    this->code_view_ = copy.code_view().clone();
  }
}

Debug& Debug::operator=(Debug other) {
  this->swap(other);
  return *this;
}


void Debug::swap(Debug& other) {
  std::swap(this->characteristics_,   other.characteristics_);
  std::swap(this->timestamp_,         other.timestamp_);
  std::swap(this->majorversion_,      other.majorversion_);
  std::swap(this->minorversion_,      other.minorversion_);
  std::swap(this->type_,              other.type_);
  std::swap(this->sizeof_data_,       other.sizeof_data_);
  std::swap(this->addressof_rawdata_, other.addressof_rawdata_);
  std::swap(this->pointerto_rawdata_, other.pointerto_rawdata_);
  std::swap(this->code_view_,         other.code_view_);
}

Debug::~Debug(void) {
  if (this->code_view_ != nullptr) {
    delete this->code_view_;
  }
}

Debug::Debug(void) :
  characteristics_{0},
  timestamp_{0},
  majorversion_{0},
  minorversion_{0},
  type_{DEBUG_TYPES::IMAGE_DEBUG_TYPE_UNKNOWN},
  sizeof_data_{0},
  addressof_rawdata_{0},
  pointerto_rawdata_{0},
  code_view_{nullptr}
{}

Debug::Debug(const pe_debug* debug_s) :
  characteristics_{debug_s->Characteristics},
  timestamp_{debug_s->TimeDateStamp},
  majorversion_{debug_s->MajorVersion},
  minorversion_{debug_s->MinorVersion},
  type_{static_cast<DEBUG_TYPES>(debug_s->Type)},
  sizeof_data_{debug_s->SizeOfData},
  addressof_rawdata_{debug_s->AddressOfRawData},
  pointerto_rawdata_{debug_s->PointerToRawData},
  code_view_{nullptr}
{}



uint32_t Debug::characteristics(void) const {
  return this->characteristics_;
}

uint32_t Debug::timestamp(void) const {
  return this->timestamp_;
}

uint16_t Debug::major_version(void) const {
  return this->majorversion_;
}

uint16_t Debug::minor_version(void) const {
  return this->minorversion_;
}

DEBUG_TYPES Debug::type(void) const {
  return this->type_;
}

uint32_t Debug::sizeof_data(void) const {
  return this->sizeof_data_;
}

uint32_t Debug::addressof_rawdata(void) const {
  return this->addressof_rawdata_;
}

uint32_t Debug::pointerto_rawdata(void) const {
  return this->pointerto_rawdata_;
}


bool Debug::has_code_view(void) const {
  return this->code_view_ != nullptr;
}

const CodeView& Debug::code_view(void) const {
  if (not this->has_code_view()) {
    throw not_found("Can't find code view");
  }

  return *this->code_view_;

}

CodeView& Debug::code_view(void) {
  return const_cast<CodeView&>(static_cast<const Debug*>(this)->code_view());
}


void Debug::characteristics(uint32_t characteristics) {
  this->characteristics_ = characteristics;
}

void Debug::timestamp(uint32_t timestamp) {
  this->timestamp_ = timestamp;
}

void Debug::major_version(uint16_t major_version) {
  this->majorversion_ = major_version;
}

void Debug::minor_version(uint16_t minor_version) {
  this->minorversion_ = minor_version;
}

void Debug::type(DEBUG_TYPES new_type) {
  this->type_ = new_type;
}

void Debug::sizeof_data(uint32_t sizeof_data) {
  this->sizeof_data_ = sizeof_data;
}

void Debug::addressof_rawdata(uint32_t addressof_rawdata) {
  this->addressof_rawdata_ = addressof_rawdata;
}

void Debug::pointerto_rawdata(uint32_t pointerto_rawdata) {
  this->pointerto_rawdata_ = pointerto_rawdata;
}


void Debug::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Debug::operator==(const Debug& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Debug::operator!=(const Debug& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Debug& entry) {

  os << std::hex;
  os << std::left;
  os << std::setfill(' ');

  os << std::setw(20) << "Characteristics:"    << entry.characteristics()             << std::endl;
  os << std::setw(20) << "Timestamp:"          << entry.timestamp()                   << std::endl;
  os << std::setw(20) << "Major version:"      << entry.major_version()               << std::endl;
  os << std::setw(20) << "Minor version:"      << entry.minor_version()               << std::endl;
  os << std::setw(20) << "Type:"               << to_string(entry.type()) << std::endl;
  os << std::setw(20) << "Size of data:"       << entry.sizeof_data()                 << std::endl;
  os << std::setw(20) << "Address of rawdata:" << entry.addressof_rawdata()           << std::endl;
  os << std::setw(20) << "Pointer to rawdata:" << entry.pointerto_rawdata()           << std::endl;

  if (entry.has_code_view()) {
    os << std::endl;
    os << entry.code_view();
    os << std::endl;
  }
  return os;
}

} // namespace PE
} // namespace LIEF
