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

LoadConfigurationV6& LoadConfigurationV6::operator=(const LoadConfigurationV6&) = default;
LoadConfigurationV6::LoadConfigurationV6(const LoadConfigurationV6&) = default;
LoadConfigurationV6::~LoadConfigurationV6() = default;

LoadConfigurationV6::LoadConfigurationV6() :
  guardrf_verify_stackpointer_function_pointer_{0},
  hotpatch_table_offset_{0}
{}


WIN_VERSION LoadConfigurationV6::version() const {
  return LoadConfigurationV6::VERSION;
}

uint64_t LoadConfigurationV6::guard_rf_verify_stackpointer_function_pointer() const {
  return guardrf_verify_stackpointer_function_pointer_;
}

uint32_t LoadConfigurationV6::hotpatch_table_offset() const {
  return hotpatch_table_offset_;
}

void LoadConfigurationV6::guard_rf_verify_stackpointer_function_pointer(uint64_t value) {
  guardrf_verify_stackpointer_function_pointer_ = value;
}

void LoadConfigurationV6::hotpatch_table_offset(uint32_t value) {
  hotpatch_table_offset_ = value;
}

void LoadConfigurationV6::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV6::operator==(const LoadConfigurationV6& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV6::operator!=(const LoadConfigurationV6& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadConfigurationV6::print(std::ostream& os) const {
  LoadConfigurationV5::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GRF verify stackpointer function pointer:" << std::hex << guard_rf_verify_stackpointer_function_pointer() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Hotpatch table offset:"                    << std::hex << hotpatch_table_offset()                         << std::endl;
  return os;
}



} // namespace PE
} // namespace LIEF

