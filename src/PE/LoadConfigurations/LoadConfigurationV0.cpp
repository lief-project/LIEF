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

LoadConfigurationV0& LoadConfigurationV0::operator=(const LoadConfigurationV0&) = default;
LoadConfigurationV0::LoadConfigurationV0(const LoadConfigurationV0&) = default;
LoadConfigurationV0::~LoadConfigurationV0() = default;

LoadConfigurationV0::LoadConfigurationV0() :
  se_handler_table_{0},
  se_handler_count_{0}
{}


WIN_VERSION LoadConfigurationV0::version() const {
  return LoadConfigurationV0::VERSION;
}

uint64_t LoadConfigurationV0::se_handler_table() const {
  return se_handler_table_;
}

uint64_t LoadConfigurationV0::se_handler_count() const {
  return se_handler_count_;
}

void LoadConfigurationV0::se_handler_table(uint64_t se_handler_table) {
  se_handler_table_ = se_handler_table;
}

void LoadConfigurationV0::se_handler_count(uint64_t se_handler_count) {
  se_handler_count_ = se_handler_count;
}

void LoadConfigurationV0::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV0::operator==(const LoadConfigurationV0& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV0::operator!=(const LoadConfigurationV0& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadConfigurationV0::print(std::ostream& os) const {
  LoadConfiguration::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "SE handler table:" << std::hex << se_handler_table() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "SE handler count:" << std::dec << se_handler_count() << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

