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

LoadConfigurationV5& LoadConfigurationV5::operator=(const LoadConfigurationV5&) = default;
LoadConfigurationV5::LoadConfigurationV5(const LoadConfigurationV5&) = default;
LoadConfigurationV5::~LoadConfigurationV5() = default;

LoadConfigurationV5::LoadConfigurationV5() :
  guard_rf_failure_routine_{0},
  guard_rf_failure_routine_function_pointer_{0},
  dynamic_value_reloctable_offset_{0},
  dynamic_value_reloctable_section_{0},
  reserved2_{0}
{}

WIN_VERSION LoadConfigurationV5::version() const {
  return LoadConfigurationV5::VERSION;
}

uint64_t LoadConfigurationV5::guard_rf_failure_routine() const {
  return guard_rf_failure_routine_;
}

uint64_t LoadConfigurationV5::guard_rf_failure_routine_function_pointer() const {
  return guard_rf_failure_routine_function_pointer_;
}

uint32_t LoadConfigurationV5::dynamic_value_reloctable_offset() const {
  return dynamic_value_reloctable_offset_;
}

uint16_t LoadConfigurationV5::dynamic_value_reloctable_section() const {
  return dynamic_value_reloctable_section_;
}

uint16_t LoadConfigurationV5::reserved2() const {
  return reserved2_;
}


void LoadConfigurationV5::guard_rf_failure_routine(uint64_t value) {
  guard_rf_failure_routine_ = value;
}

void LoadConfigurationV5::guard_rf_failure_routine_function_pointer(uint64_t value) {
  guard_rf_failure_routine_function_pointer_ = value;
}

void LoadConfigurationV5::dynamic_value_reloctable_offset(uint32_t value) {
  dynamic_value_reloctable_offset_ = value;
}

void LoadConfigurationV5::dynamic_value_reloctable_section(uint16_t value) {
  dynamic_value_reloctable_section_ = value;
}

void LoadConfigurationV5::reserved2(uint16_t value) {
  reserved2_ = value;
}



void LoadConfigurationV5::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV5::operator==(const LoadConfigurationV5& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV5::operator!=(const LoadConfigurationV5& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadConfigurationV5::print(std::ostream& os) const {
  LoadConfigurationV4::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GRF failure routine:"                  << std::hex << guard_rf_failure_routine()                  << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GRF failure routine function pointer:" << std::hex << guard_rf_failure_routine_function_pointer() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Dynamic value reloctable offset:"      << std::hex << dynamic_value_reloctable_offset()           << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Dynamic value reloctable section:"     << std::dec << dynamic_value_reloctable_section()          << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

