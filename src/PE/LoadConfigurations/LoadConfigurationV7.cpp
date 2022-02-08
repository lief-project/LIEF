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

#include "LIEF/PE/LoadConfigurations.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV7& LoadConfigurationV7::operator=(const LoadConfigurationV7&) = default;
LoadConfigurationV7::LoadConfigurationV7(const LoadConfigurationV7&) = default;
LoadConfigurationV7::~LoadConfigurationV7() = default;

LoadConfigurationV7::LoadConfigurationV7() :
  reserved3_{0},
  addressof_unicode_string_{0}
{}

WIN_VERSION LoadConfigurationV7::version() const {
  return LoadConfigurationV7::VERSION;
}

uint32_t LoadConfigurationV7::reserved3() const {
  return reserved3_;
}

uint64_t LoadConfigurationV7::addressof_unicode_string() const {
  return addressof_unicode_string_;
}

void LoadConfigurationV7::reserved3(uint32_t value) {
  reserved3_ = value;
}

void LoadConfigurationV7::addressof_unicode_string(uint64_t value) {
  addressof_unicode_string_ = value;
}

void LoadConfigurationV7::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV7::operator==(const LoadConfigurationV7& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV7::operator!=(const LoadConfigurationV7& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadConfigurationV7::print(std::ostream& os) const {
  LoadConfigurationV6::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Reserved 3:" << std::hex << reserved3() << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

