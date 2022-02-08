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
  NoteDetails::NoteDetails{note}
{}

AndroidNote* AndroidNote::clone() const {
  return new AndroidNote(*this);
}

uint32_t AndroidNote::sdk_version() const {
  return sdk_version_;
}

std::string AndroidNote::ndk_version() const {
  return ndk_version_;
}

std::string AndroidNote::ndk_build_number() const {
  return ndk_build_number_;
}

void AndroidNote::sdk_version(uint32_t version) {
  sdk_version_ = version;
  build();
}

void AndroidNote::ndk_version(const std::string& ndk_version) {
  ndk_version_ = ndk_version;
  build();
}

void AndroidNote::ndk_build_number(const std::string& ndk_build_number) {
  ndk_build_number_ = ndk_build_number;
  build();
}


void AndroidNote::parse() {
  const description_t& desc = description();

  // Parse SDK Version
  if (desc.size() < (sdk_version_offset + sdk_version_size)) {
    return;
  }
  sdk_version_ = *reinterpret_cast<const uint32_t*>(desc.data() + sdk_version_offset);

  // Parse NDK Version
  if (desc.size() < (ndk_version_offset + ndk_version_size)) {
    return ;
  }
  ndk_version_ = std::string{reinterpret_cast<const char*>(desc.data()) + ndk_version_offset, ndk_version_size};

  // Parse NDK Build Number
  if (desc.size() < (ndk_build_number_offset + ndk_build_number_size)) {
    return ;
  }
  ndk_build_number_ = std::string{reinterpret_cast<const char*>(desc.data()) + ndk_build_number_offset, ndk_build_number_size};
}

void AndroidNote::build() {
  description_t& desc = description();

  // Build SDK Version
  // =================
  if (desc.size() < (sdk_version_offset + sdk_version_size)) {
    desc.resize(sdk_version_offset + sdk_version_size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(&sdk_version_),
      reinterpret_cast<const uint8_t*>(&sdk_version_) + sdk_version_size,
      desc.data() + sdk_version_offset);

  // Build NDK Version
  // =================
  if (desc.size() < (ndk_version_offset + ndk_version_size)) {
    desc.resize(ndk_version_offset + ndk_version_size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(ndk_version_.data()),
      reinterpret_cast<const uint8_t*>(ndk_version_.data()) + ndk_version_.size(),
      desc.data() + ndk_version_offset);

  // Build NDK Build Number
  // ======================
  if (desc.size() < (ndk_build_number_offset + ndk_build_number_size)) {
    desc.resize(ndk_build_number_offset + ndk_build_number_size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(ndk_build_number_.data()),
      reinterpret_cast<const uint8_t*>(ndk_build_number_.data()) + ndk_build_number_.size(),
      desc.data() + ndk_build_number_offset);
}

void AndroidNote::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool AndroidNote::operator==(const AndroidNote& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool AndroidNote::operator!=(const AndroidNote& rhs) const {
  return !(*this == rhs);
}

void AndroidNote::dump(std::ostream& os) const {
  os << std::setw(33) << std::setfill(' ') << "SDK Version: " << std::dec << sdk_version() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "NDK Version: " << ndk_version() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "NDK Builder Number: " << ndk_build_number() << std::endl;
}

std::ostream& operator<<(std::ostream& os, const AndroidNote& note) {
  note.dump(os);
  return os;
}

AndroidNote::~AndroidNote() = default;

} // namespace ELF
} // namespace LIEF
