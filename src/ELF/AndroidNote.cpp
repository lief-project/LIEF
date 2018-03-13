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
#include <numeric>
#include <sstream>
#include <algorithm>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/AndroidNote.hpp"

namespace LIEF {
namespace ELF {

uint32_t AndroidNote::sdk_version(void) const {
  const Note::description_t& description = this->description();

  if (description.size() < sizeof(uint32_t)) {
    return -1u;
  }
  uint32_t version = *reinterpret_cast<const uint32_t*>(description.data());

  return version;
}

std::string AndroidNote::ndk_version(void) const {
  static constexpr size_t offset = sizeof(uint32_t);
  static constexpr size_t size   = 64 * sizeof(char);

  const Note::description_t& description = this->description();

  if (description.size() < (offset + size)) {
    return "";
  }
  return std::string{reinterpret_cast<const char*>(description.data()) + offset, size};
}

std::string AndroidNote::ndk_build_number(void) const {
  static constexpr size_t offset = sizeof(uint32_t) + 64 * sizeof(char);
  static constexpr size_t size   = 64 * sizeof(char);

  const Note::description_t& description = this->description();

  if (description.size() < (offset + size)) {
    return "";
  }
  return std::string{reinterpret_cast<const char*>(description.data()) + offset, size};
}

void AndroidNote::sdk_version(uint32_t version) {
  description_t& description = this->description();

  if (description.size() < sizeof(uint32_t)) {
    description.resize(sizeof(uint32_t));
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(&version),
      reinterpret_cast<const uint8_t*>(&version) + sizeof(uint32_t),
      description.data());

}

void AndroidNote::ndk_version(const std::string& ndk_version) {
  static constexpr size_t offset = sizeof(uint32_t);
  static constexpr size_t size = 64 * sizeof(char);
  description_t& description = this->description();

  if (description.size() < (offset + size)) {
    description.resize(offset + size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(ndk_version.data()),
      reinterpret_cast<const uint8_t*>(ndk_version.data()) + ndk_version.size(),
      description.data() + offset);
}

void AndroidNote::ndk_build_number(const std::string& ndk_build_number) {
  static constexpr size_t offset = sizeof(uint32_t) + 64 * sizeof(char);
  static constexpr size_t size   = 64 * sizeof(char);
  description_t& description = this->description();

  if (description.size() < (offset + size)) {
    description.resize(offset + size);
  }

  std::copy(
      reinterpret_cast<const uint8_t*>(ndk_build_number.data()),
      reinterpret_cast<const uint8_t*>(ndk_build_number.data()) + ndk_build_number.size(),
      description.data() + offset);
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
  Note::dump(os);

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
