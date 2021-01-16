/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include <numeric>
#include <sstream>
#include <algorithm>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/NoteDetails/AndroidNote.hpp"

namespace LIEF {
namespace ELF {

AndroidNote AndroidNote::make(Note& note) {
  AndroidNote android_note = note;
  android_note.parse();
  return android_note;
}

AndroidNote::AndroidNote(Note& note) :
  NoteDetails::NoteDetails{note},
  sdk_version_{0},
  ndk_version_{},
  ndk_build_number_{}
{}

AndroidNote* AndroidNote::clone(void) const {
  return new AndroidNote(*this);
}

uint32_t AndroidNote::sdk_version(void) const {
  return this->sdk_version_;
}

std::string AndroidNote::ndk_version(void) const {
  return this->ndk_version_;
}

std::string AndroidNote::ndk_build_number(void) const {
  return this->ndk_build_number_;
}

void AndroidNote::sdk_version(uint32_t version) {
  this->sdk_version_ = version;
  this->build();
}

void AndroidNote::ndk_version(const std::string& ndk_version) {
  this->ndk_version_ = ndk_version;
  this->build();
}

void AndroidNote::ndk_build_number(const std::string& ndk_build_number) {
  this->ndk_build_number_ = ndk_build_number;
  this->build();
}


void AndroidNote::parse(void) {
  const description_t& description = this->description();

  // Parse SDK Version
  if (description.size() < (sdk_version_offset + sdk_version_size)) {
    return;
  }
  this->sdk_version_ = *reinterpret_cast<const uint32_t*>(description.data() + sdk_version_offset);

  // Parse NDK Version
  if (description.size() < (ndk_version_offset + ndk_version_size)) {
    return ;
  }
  this->ndk_version_ = std::string{reinterpret_cast<const char*>(description.data()) + ndk_version_offset, ndk_version_size};

  // Parse NDK Build Number
  if (description.size() < (ndk_build_number_offset + ndk_build_number_size)) {
    return ;
  }
  this->ndk_build_number_ = std::string{reinterpret_cast<const char*>(description.data()) + ndk_build_number_offset, ndk_build_number_size};
}

void AndroidNote::build(void) {
  description_t& description = this->description();

  // Build SDK Version
  // =================
  if (description.size() < (sdk_version_offset + sdk_version_size)) {
    description.resize(sdk_version_offset + sdk_version_size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(&this->sdk_version_),
      reinterpret_cast<const uint8_t*>(&this->sdk_version_) + sdk_version_size,
      description.data() + sdk_version_offset);

  // Build NDK Version
  // =================
  if (description.size() < (ndk_version_offset + ndk_version_size)) {
    description.resize(ndk_version_offset + ndk_version_size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(this->ndk_version_.data()),
      reinterpret_cast<const uint8_t*>(this->ndk_version_.data()) + this->ndk_version_.size(),
      description.data() + ndk_version_offset);

  // Build NDK Build Number
  // ======================
  if (description.size() < (ndk_build_number_offset + ndk_build_number_size)) {
    description.resize(ndk_build_number_offset + ndk_build_number_size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(this->ndk_build_number_.data()),
      reinterpret_cast<const uint8_t*>(this->ndk_build_number_.data()) + this->ndk_build_number_.size(),
      description.data() + ndk_build_number_offset);
}

void AndroidNote::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool AndroidNote::operator==(const AndroidNote& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool AndroidNote::operator!=(const AndroidNote& rhs) const {
  return not (*this == rhs);
}

void AndroidNote::dump(std::ostream& os) const {
  os << std::setw(33) << std::setfill(' ') << "SDK Version: " << std::dec << this->sdk_version() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "NDK Version: " << this->ndk_version() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "NDK Builder Number: " << this->ndk_build_number() << std::endl;
}

std::ostream& operator<<(std::ostream& os, const AndroidNote& note) {
  note.dump(os);
  return os;
}

AndroidNote::~AndroidNote(void) = default;

} // namespace ELF
} // namespace LIEF
