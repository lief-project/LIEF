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
#include "LIEF/exception.hpp"

#include "LIEF/PE/LoadConfigurations.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV3& LoadConfigurationV3::operator=(const LoadConfigurationV3&) = default;
LoadConfigurationV3::LoadConfigurationV3(const LoadConfigurationV3&) = default;
LoadConfigurationV3::~LoadConfigurationV3(void) = default;

LoadConfigurationV3::LoadConfigurationV3(void) :
  LoadConfigurationV2{},
  guard_address_taken_iat_entry_table_{0},
  guard_address_taken_iat_entry_count_{0},
  guard_long_jump_target_table_{0},
  guard_long_jump_target_count_{0}
{}

WIN_VERSION LoadConfigurationV3::version(void) const {
  return LoadConfigurationV3::VERSION;
}

uint64_t LoadConfigurationV3::guard_address_taken_iat_entry_table(void) const {
  return this->guard_address_taken_iat_entry_table_;
}

uint64_t LoadConfigurationV3::guard_address_taken_iat_entry_count(void) const {
  return this->guard_address_taken_iat_entry_count_;
}

uint64_t LoadConfigurationV3::guard_long_jump_target_table(void) const {
  return this->guard_long_jump_target_table_;
}

uint64_t LoadConfigurationV3::guard_long_jump_target_count(void) const {
  return this->guard_long_jump_target_count_;
}

void LoadConfigurationV3::guard_address_taken_iat_entry_table(uint64_t value) {
  this->guard_address_taken_iat_entry_table_ = value;
}

void LoadConfigurationV3::guard_address_taken_iat_entry_count(uint64_t value) {
  this->guard_address_taken_iat_entry_count_ = value;
}

void LoadConfigurationV3::guard_long_jump_target_table(uint64_t value) {
  this->guard_long_jump_target_table_ = value;
}

void LoadConfigurationV3::guard_long_jump_target_count(uint64_t value) {
  this->guard_long_jump_target_count_ = value;
}


void LoadConfigurationV3::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV3::operator==(const LoadConfigurationV3& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV3::operator!=(const LoadConfigurationV3& rhs) const {
  return not (*this == rhs);
}

std::ostream& LoadConfigurationV3::print(std::ostream& os) const {
  LoadConfigurationV2::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Guard address taken iat entry table:" << std::hex << this->guard_address_taken_iat_entry_table() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Guard address taken iat entry count:" << std::dec << this->guard_address_taken_iat_entry_count() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Guard long jump target table:"        << std::hex << this->guard_long_jump_target_table()        << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Guard long jump target count:"        << std::dec << this->guard_long_jump_target_count()        << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

