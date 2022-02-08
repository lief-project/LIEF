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
#include <numeric>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV1& LoadConfigurationV1::operator=(const LoadConfigurationV1&) = default;
LoadConfigurationV1::LoadConfigurationV1(const LoadConfigurationV1&) = default;
LoadConfigurationV1::~LoadConfigurationV1() = default;

LoadConfigurationV1::LoadConfigurationV1() :
  guard_cf_check_function_pointer_{0},
  guard_cf_dispatch_function_pointer_{0},
  guard_cf_function_table_{0},
  guard_cf_function_count_{0},
  guard_flags_{GUARD_CF_FLAGS::GCF_NONE}
{}


WIN_VERSION LoadConfigurationV1::version() const {
  return LoadConfigurationV1::VERSION;
}

uint64_t LoadConfigurationV1::guard_cf_check_function_pointer() const {
  return guard_cf_check_function_pointer_;
}

uint64_t LoadConfigurationV1::guard_cf_dispatch_function_pointer() const {
  return guard_cf_dispatch_function_pointer_;
}

uint64_t LoadConfigurationV1::guard_cf_function_table() const {
  return guard_cf_function_table_;
}

uint64_t LoadConfigurationV1::guard_cf_function_count() const {
  return guard_cf_function_count_;
}

GUARD_CF_FLAGS LoadConfigurationV1::guard_flags() const {
  return guard_flags_;
}


bool LoadConfigurationV1::has(GUARD_CF_FLAGS flag) const {
  return (guard_flags() & flag) != GUARD_CF_FLAGS::GCF_NONE;
}

LoadConfigurationV1::guard_cf_flags_list_t LoadConfigurationV1::guard_cf_flags_list() const {

  guard_cf_flags_list_t flags;

  std::copy_if(std::begin(guard_cf_flags_array), std::end(guard_cf_flags_array),
               std::inserter(flags, std::begin(flags)),
               [this] (GUARD_CF_FLAGS f) { return has(f); });

  return flags;
}

void LoadConfigurationV1::guard_cf_check_function_pointer(uint64_t guard_cf_check_function_pointer) {
  guard_cf_check_function_pointer_ = guard_cf_check_function_pointer;
}

void LoadConfigurationV1::guard_cf_dispatch_function_pointer(uint64_t guard_cf_dispatch_function_pointer) {
  guard_cf_dispatch_function_pointer_ = guard_cf_dispatch_function_pointer;
}

void LoadConfigurationV1::guard_cf_function_table(uint64_t guard_cf_function_table) {
  guard_cf_function_table_ = guard_cf_function_table;
}

void LoadConfigurationV1::guard_cf_function_count(uint64_t guard_cf_function_count) {
  guard_cf_function_count_ = guard_cf_function_count;
}

void LoadConfigurationV1::guard_flags(GUARD_CF_FLAGS guard_flags) {
  guard_flags_ = guard_flags;
}

void LoadConfigurationV1::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV1::operator==(const LoadConfigurationV1& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfigurationV1::operator!=(const LoadConfigurationV1& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadConfigurationV1::print(std::ostream& os) const {
  LoadConfigurationV0::print(os);


  const guard_cf_flags_list_t& flags = guard_cf_flags_list();
  std::string flags_str = std::accumulate(
     std::begin(flags), std::end(flags), std::string{},
     [] (const std::string& a, GUARD_CF_FLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF check function pointer:"    << std::hex << guard_cf_check_function_pointer()    << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF dispatch function pointer:" << std::hex << guard_cf_dispatch_function_pointer() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF function table :"           << std::hex << guard_cf_function_table()            << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GCF Function count:"            << std::dec << guard_cf_function_count()            << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Guard flags:"                   << std::hex << flags_str << " (" << static_cast<size_t>(guard_flags()) << ")" << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

