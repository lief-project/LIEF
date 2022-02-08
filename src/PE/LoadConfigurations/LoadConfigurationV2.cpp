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
#include "LIEF/exception.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/PE/LoadConfigurations.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV2& LoadConfigurationV2::operator=(const LoadConfigurationV2&) = default;
LoadConfigurationV2::LoadConfigurationV2(const LoadConfigurationV2&) = default;
LoadConfigurationV2::~LoadConfigurationV2() = default;

LoadConfigurationV2::LoadConfigurationV2() = default;

WIN_VERSION LoadConfigurationV2::version() const {
  return LoadConfigurationV2::VERSION;
}


const CodeIntegrity& LoadConfigurationV2::code_integrity() const {
  return code_integrity_;
}

CodeIntegrity& LoadConfigurationV2::code_integrity() {
  return const_cast<CodeIntegrity&>(static_cast<const LoadConfigurationV2*>(this)->code_integrity());
}

void LoadConfigurationV2::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV2::operator==(const LoadConfigurationV2& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV2::operator!=(const LoadConfigurationV2& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadConfigurationV2::print(std::ostream& os) const {
  LoadConfigurationV1::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Code Integrity:" << std::endl;
  os << code_integrity();
  return os;
}



} // namespace PE
} // namespace LIEF

