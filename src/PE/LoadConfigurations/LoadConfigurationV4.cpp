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

LoadConfigurationV4& LoadConfigurationV4::operator=(const LoadConfigurationV4&) = default;
LoadConfigurationV4::LoadConfigurationV4(const LoadConfigurationV4&) = default;
LoadConfigurationV4::~LoadConfigurationV4(void) = default;

LoadConfigurationV4::LoadConfigurationV4(void) :
  LoadConfigurationV3{},
  dynamic_value_reloc_table_{0},
  hybrid_metadata_pointer_{0}
{}

WIN_VERSION LoadConfigurationV4::version(void) const {
  return LoadConfigurationV4::VERSION;
}

uint64_t LoadConfigurationV4::dynamic_value_reloc_table(void) const {
  return this->dynamic_value_reloc_table_;
}

uint64_t LoadConfigurationV4::hybrid_metadata_pointer(void) const {
  return this->hybrid_metadata_pointer_;
}

void LoadConfigurationV4::dynamic_value_reloc_table(uint64_t value) {
  this->dynamic_value_reloc_table_ = value;
}

void LoadConfigurationV4::hybrid_metadata_pointer(uint64_t value) {
  this->hybrid_metadata_pointer_ = value;
}

void LoadConfigurationV4::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV4::operator==(const LoadConfigurationV4& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV4::operator!=(const LoadConfigurationV4& rhs) const {
  return not (*this == rhs);
}

std::ostream& LoadConfigurationV4::print(std::ostream& os) const {
  LoadConfigurationV3::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Dynamic value relocation table:" << std::hex << this->dynamic_value_reloc_table() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Hybrid metadata pointer:"        << std::hex << this->hybrid_metadata_pointer()   << std::endl;
  return os;
}



} // namespace PE
} // namespace LIEF

