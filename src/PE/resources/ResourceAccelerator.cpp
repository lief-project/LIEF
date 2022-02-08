/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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

#include "LIEF/exception.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"

#include "LIEF/PE/resources/ResourceAccelerator.hpp"

namespace LIEF {
namespace PE {

ResourceAccelerator::ResourceAccelerator(const ResourceAccelerator&) = default;
ResourceAccelerator& ResourceAccelerator::operator=(const ResourceAccelerator&) = default;
ResourceAccelerator::~ResourceAccelerator() = default;

ResourceAccelerator::ResourceAccelerator() :
  flags_{0},
  ansi_{0},
  id_{0},
  padding_{0} {}

ResourceAccelerator::ResourceAccelerator(const details::pe_resource_acceltableentry& entry) :
  flags_{entry.fFlags},
  ansi_{entry.wAnsi},
  id_{static_cast<uint16_t>(entry.wId)},
  padding_{entry.padding} {}

void ResourceAccelerator::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceAccelerator::operator==(const ResourceAccelerator& rhs) const {
  if (this == &rhs) {
    return true;
  }
  const auto hash_lhs = Hash::hash(*this);
  const auto hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceAccelerator::operator!=(const ResourceAccelerator& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceAccelerator& acc) {
  os << "flags: ";
  for (const ACCELERATOR_FLAGS c : acc.flags_list()) {
    os << to_string(c) << " ";
  }
  os << std::endl;
  os << "ansi: " << acc.ansi_str() << std::endl;
  os << std::hex << "id: " << acc.id() << std::endl;
  os << std::hex << "padding: " << acc.padding() << std::endl;
  return os;
}

std::string ResourceAccelerator::ansi_str() const {
  return to_string(static_cast<ACCELERATOR_VK_CODES>(ansi_));
}

std::set<ACCELERATOR_FLAGS> ResourceAccelerator::flags_list() const {
  std::set<ACCELERATOR_FLAGS> flags_set;

  const auto flags_tmp = flags_;
  std::copy_if(
    std::cbegin(details::accelerator_array),
    std::cend(details::accelerator_array),
    std::inserter(flags_set, std::begin(flags_set)),
    [flags_tmp](ACCELERATOR_FLAGS c) {
      return (static_cast<uint16_t>(flags_tmp) & static_cast<uint16_t>(c)) > 0;
    }
  );
  return flags_set;
}

int16_t ResourceAccelerator::flags() const {
  return flags_;
}

int16_t ResourceAccelerator::ansi() const {
  return ansi_;
}

uint16_t ResourceAccelerator::id() const {
  return id_;
}

int16_t ResourceAccelerator::padding() const {
  return padding_;
}

}
}
