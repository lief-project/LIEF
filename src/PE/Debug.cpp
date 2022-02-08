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

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Debug.hpp"
#include "LIEF/PE/CodeView.hpp"
#include "LIEF/PE/Pogo.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

Debug::Debug() = default;
Debug::~Debug() = default;

Debug::Debug(const Debug& copy) :
  Object{copy},
  characteristics_{copy.characteristics_},
  timestamp_{copy.timestamp_},
  majorversion_{copy.majorversion_},
  minorversion_{copy.minorversion_},
  type_{copy.type_},
  sizeof_data_{copy.sizeof_data_},
  addressof_rawdata_{copy.addressof_rawdata_},
  pointerto_rawdata_{copy.pointerto_rawdata_}
{
  if (copy.has_code_view()) {
    code_view_ = std::unique_ptr<CodeView>(copy.code_view()->clone());
  }

  if (copy.has_pogo()) {
    pogo_ = std::unique_ptr<Pogo>(copy.pogo()->clone());
  }
}

Debug& Debug::operator=(Debug other) {
  swap(other);
  return *this;
}


void Debug::swap(Debug& other) {
  std::swap(characteristics_,   other.characteristics_);
  std::swap(timestamp_,         other.timestamp_);
  std::swap(majorversion_,      other.majorversion_);
  std::swap(minorversion_,      other.minorversion_);
  std::swap(type_,              other.type_);
  std::swap(sizeof_data_,       other.sizeof_data_);
  std::swap(addressof_rawdata_, other.addressof_rawdata_);
  std::swap(pointerto_rawdata_, other.pointerto_rawdata_);
  std::swap(code_view_,         other.code_view_);
  std::swap(pogo_,              other.pogo_);
}


Debug::Debug(const details::pe_debug& debug_s) :
  characteristics_{debug_s.Characteristics},
  timestamp_{debug_s.TimeDateStamp},
  majorversion_{debug_s.MajorVersion},
  minorversion_{debug_s.MinorVersion},
  type_{static_cast<DEBUG_TYPES>(debug_s.Type)},
  sizeof_data_{debug_s.SizeOfData},
  addressof_rawdata_{debug_s.AddressOfRawData},
  pointerto_rawdata_{debug_s.PointerToRawData}
{}



uint32_t Debug::characteristics() const {
  return characteristics_;
}

uint32_t Debug::timestamp() const {
  return timestamp_;
}

uint16_t Debug::major_version() const {
  return majorversion_;
}

uint16_t Debug::minor_version() const {
  return minorversion_;
}

DEBUG_TYPES Debug::type() const {
  return type_;
}

uint32_t Debug::sizeof_data() const {
  return sizeof_data_;
}

uint32_t Debug::addressof_rawdata() const {
  return addressof_rawdata_;
}

uint32_t Debug::pointerto_rawdata() const {
  return pointerto_rawdata_;
}


bool Debug::has_code_view() const {
  return code_view_ != nullptr;
}

const CodeView* Debug::code_view() const {
  return code_view_.get();

}

CodeView* Debug::code_view() {
  return const_cast<CodeView*>(static_cast<const Debug*>(this)->code_view());
}

bool Debug::has_pogo() const {
  return pogo_ != nullptr;
}

const Pogo* Debug::pogo() const {
  return pogo_.get();
}

Pogo* Debug::pogo() {
  return const_cast<Pogo*>(static_cast<const Debug*>(this)->pogo());
}


void Debug::characteristics(uint32_t characteristics) {
  characteristics_ = characteristics;
}

void Debug::timestamp(uint32_t timestamp) {
  timestamp_ = timestamp;
}

void Debug::major_version(uint16_t major_version) {
  majorversion_ = major_version;
}

void Debug::minor_version(uint16_t minor_version) {
  minorversion_ = minor_version;
}

void Debug::type(DEBUG_TYPES new_type) {
  type_ = new_type;
}

void Debug::sizeof_data(uint32_t sizeof_data) {
  sizeof_data_ = sizeof_data;
}

void Debug::addressof_rawdata(uint32_t addressof_rawdata) {
  addressof_rawdata_ = addressof_rawdata;
}

void Debug::pointerto_rawdata(uint32_t pointerto_rawdata) {
  pointerto_rawdata_ = pointerto_rawdata;
}


void Debug::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Debug::operator==(const Debug& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Debug::operator!=(const Debug& rhs) const {
  return !(*this == rhs);
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
    os << *entry.code_view();
    os << std::endl;
  }

  if (entry.has_pogo()) {
    os << std::endl;
    os << *entry.pogo();
    os << std::endl;
  }

  return os;
}

} // namespace PE
} // namespace LIEF
