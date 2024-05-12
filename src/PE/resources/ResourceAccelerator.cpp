/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <algorithm>

#include "LIEF/Visitor.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"

#include "LIEF/PE/resources/ResourceAccelerator.hpp"

namespace LIEF {
namespace PE {

ResourceAccelerator::ResourceAccelerator(const details::pe_resource_acceltableentry& entry) :
  flags_{entry.fFlags},
  ansi_{entry.wAnsi},
  id_{static_cast<uint16_t>(entry.wId)},
  padding_{entry.padding} {}

void ResourceAccelerator::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const ResourceAccelerator& acc) {
  os << "flags: ";
  for (const ACCELERATOR_FLAGS c : acc.flags_list()) {
    os << to_string(c) << " ";
  }
  os << '\n';
  os << "ansi: " << acc.ansi_str() << '\n';
  os << std::hex << "id: " << acc.id() << '\n';
  os << std::hex << "padding: " << acc.padding() << '\n';
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

}
}
