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

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV1& LoadConfigurationV1::operator=(const LoadConfigurationV1&) = default;
LoadConfigurationV1::LoadConfigurationV1(const LoadConfigurationV1&) = default;
LoadConfigurationV1::~LoadConfigurationV1(void) = default;

LoadConfigurationV1::LoadConfigurationV1(void) :
  LoadConfigurationV0{},
  guard_cf_check_function_pointer_{0},
  guard_cf_dispatch_function_pointer_{0},
  guard_cf_function_table_{0},
  guard_cf_function_count_{0},
  guard_flags_{GUARD_CF_FLAGS::GCF_NONE}
{}


WIN_VERSION LoadConfigurationV1::version(void) const {
  return LoadConfigurationV1::VERSION;
}

uint64_t LoadConfigurationV1::guard_cf_check_function_pointer(void) const {
  return this->guard_cf_check_function_pointer_;
}

uint64_t LoadConfigurationV1::guard_cf_dispatch_function_pointer(void) const {
  return this->guard_cf_dispatch_function_pointer_;
}

uint64_t LoadConfigurationV1::guard_cf_function_table(void) const {
  return this->guard_cf_function_table_;
}

uint64_t LoadConfigurationV1::guard_cf_function_count(void) const {
  return this->guard_cf_function_count_;
}

GUARD_CF_FLAGS LoadConfigurationV1::guard_flags(void) const {
  return this->guard_flags_;
}


bool LoadConfigurationV1::has(GUARD_CF_FLAGS flag) const {
  return (this->guard_flags() & flag) != GUARD_CF_FLAGS::GCF_NONE;
}

guard_cf_flags_list_t LoadConfigurationV1::guard_cf_flags_list(void) const {

  guard_cf_flags_list_t flags;

  std::copy_if(
      std::begin(guard_cf_flags_array),
      std::end(guard_cf_flags_array),
      std::inserter(flags, std::begin(flags)),
      std::bind(static_cast<bool (LoadConfigurationV1::*)(GUARD_CF_FLAGS) const>(&LoadConfigurationV1::has),
        this, std::placeholders::_1));

  return flags;
}

void LoadConfigurationV1::guard_cf_check_function_pointer(uint64_t guard_cf_check_function_pointer) {
  this->guard_cf_check_function_pointer_ = guard_cf_check_function_pointer;
}

void LoadConfigurationV1::guard_cf_dispatch_function_pointer(uint64_t guard_cf_dispatch_function_pointer) {
  this->guard_cf_dispatch_function_pointer_ = guard_cf_dispatch_function_pointer;
}

void LoadConfigurationV1::guard_cf_function_table(uint64_t guard_cf_function_table) {
  this->guard_cf_function_table_ = guard_cf_function_table;
}

void LoadConfigurationV1::guard_cf_function_count(uint64_t guard_cf_function_count) {
  this->guard_cf_function_count_ = guard_cf_function_count;
}

void LoadConfigurationV1::guard_flags(GUARD_CF_FLAGS guard_flags) {
  this->guard_flags_ = guard_flags;
}

void LoadConfigurationV1::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV1::operator==(const LoadConfigurationV1& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV1::operator!=(const LoadConfigurationV1& rhs) const {
  return not (*this == rhs);
}

std::ostream& LoadConfigurationV1::print(std::ostream& os) const {
  LoadConfigurationV0::print(os);


  const guard_cf_flags_list_t& flags = this->guard_cf_flags_list();
  std::string flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
     [] (const std::string& a, GUARD_CF_FLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF check function pointer:"    << std::hex << this->guard_cf_check_function_pointer()    << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF dispatch function pointer:" << std::hex << this->guard_cf_dispatch_function_pointer() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF function table :"           << std::hex << this->guard_cf_function_table()            << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF Function count:"            << std::dec << this->guard_cf_function_count()            << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Guard flags:"                   << std::hex << flags_str << " (" << static_cast<size_t>(this->guard_flags()) << ")" << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

