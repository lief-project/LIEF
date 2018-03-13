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
#include "LIEF/PE/EnumToString.hpp"

namespace LIEF {
namespace PE {

LoadConfiguration& LoadConfiguration::operator=(const LoadConfiguration&) = default;
LoadConfiguration::LoadConfiguration(const LoadConfiguration&)            = default;
LoadConfiguration::~LoadConfiguration(void)                               = default;

decltype(PE32::load_configuration_sizes) PE32::load_configuration_sizes = {
  {WIN_VERSION::WIN_UNKNOWN,   sizeof(PE32::load_configuration_t)},
  {WIN_VERSION::WIN_SEH,       sizeof(PE32::load_configuration_v0_t)},
  {WIN_VERSION::WIN8_1,        sizeof(PE32::load_configuration_v1_t)},
  {WIN_VERSION::WIN10_0_9879,  sizeof(PE32::load_configuration_v2_t)},
  {WIN_VERSION::WIN10_0_14286, sizeof(PE32::load_configuration_v3_t)},
  {WIN_VERSION::WIN10_0_14383, sizeof(PE32::load_configuration_v4_t)},
  {WIN_VERSION::WIN10_0_14901, sizeof(PE32::load_configuration_v5_t)},
  {WIN_VERSION::WIN10_0_15002, sizeof(PE32::load_configuration_v6_t)},
  {WIN_VERSION::WIN10_0_16237, sizeof(PE32::load_configuration_v7_t)},
};


decltype(PE64::load_configuration_sizes) PE64::load_configuration_sizes = {
  {WIN_VERSION::WIN_UNKNOWN,   sizeof(PE64::load_configuration_t)},
  {WIN_VERSION::WIN_SEH,       sizeof(PE64::load_configuration_v0_t)},
  {WIN_VERSION::WIN8_1,        sizeof(PE64::load_configuration_v1_t)},
  {WIN_VERSION::WIN10_0_9879,  sizeof(PE64::load_configuration_v2_t)},
  {WIN_VERSION::WIN10_0_14286, sizeof(PE64::load_configuration_v3_t)},
  {WIN_VERSION::WIN10_0_14383, sizeof(PE64::load_configuration_v4_t)},
  {WIN_VERSION::WIN10_0_14901, sizeof(PE64::load_configuration_v5_t)},
  {WIN_VERSION::WIN10_0_15002, sizeof(PE64::load_configuration_v6_t)},
  {WIN_VERSION::WIN10_0_16237, sizeof(PE64::load_configuration_v7_t)},
};

LoadConfiguration::LoadConfiguration(void) :
  characteristics_{0},
  timedatestamp_{0},
  major_version_{0},
  minor_version_{0},
  global_flags_clear_{0},
  global_flags_set_{0},
  critical_section_default_timeout_{0},
  decommit_free_block_threshold_{0},
  decommit_total_free_threshold_{0},
  lock_prefix_table_{0},
  maximum_allocation_size_{0},
  virtual_memory_threshold_{0},
  process_affinity_mask_{0},
  process_heap_flags_{0},
  csd_version_{0},
  reserved1_{0},
  editlist_{0},
  security_cookie_{0}
{}

WIN_VERSION LoadConfiguration::version(void) const {
  return LoadConfiguration::VERSION;
}

uint32_t LoadConfiguration::characteristics(void) const {
  return this->characteristics_;
}

uint32_t LoadConfiguration::timedatestamp(void) const {
  return this->timedatestamp_;
}

uint16_t LoadConfiguration::major_version(void) const {
  return this->major_version_;
}

uint16_t LoadConfiguration::minor_version(void) const {
  return this->minor_version_;
}

uint32_t LoadConfiguration::global_flags_clear(void) const {
  return this->global_flags_clear_;
}

uint32_t LoadConfiguration::global_flags_set(void) const {
  return this->global_flags_set_;
}

uint32_t LoadConfiguration::critical_section_default_timeout(void) const {
  return this->critical_section_default_timeout_;
}

uint64_t LoadConfiguration::decommit_free_block_threshold(void) const {
  return this->decommit_free_block_threshold_;
}

uint64_t LoadConfiguration::decommit_total_free_threshold(void) const {
  return this->decommit_total_free_threshold_;
}

uint64_t LoadConfiguration::lock_prefix_table(void) const {
  return this->lock_prefix_table_;
}

uint64_t LoadConfiguration::maximum_allocation_size(void) const {
  return this->maximum_allocation_size_;
}

uint64_t LoadConfiguration::virtual_memory_threshold(void) const {
  return this->virtual_memory_threshold_;
}

uint64_t LoadConfiguration::process_affinity_mask(void) const {
  return this->process_affinity_mask_;
}

uint32_t LoadConfiguration::process_heap_flags(void) const {
  return this->process_heap_flags_;
}

uint16_t LoadConfiguration::csd_version(void) const {
  return this->csd_version_;
}

uint16_t LoadConfiguration::reserved1(void) const {
  return this->reserved1_;
}

uint32_t LoadConfiguration::editlist(void) const {
  return this->editlist_;
}

uint32_t LoadConfiguration::security_cookie(void) const {
  return this->security_cookie_;
}



void LoadConfiguration::characteristics(uint32_t characteristics) {
  this->characteristics_ = characteristics;
}

void LoadConfiguration::timedatestamp(uint32_t timedatestamp) {
  this->timedatestamp_ = timedatestamp;
}

void LoadConfiguration::major_version(uint16_t major_version) {
  this->major_version_ = major_version;
}

void LoadConfiguration::minor_version(uint16_t minor_version) {
  this->minor_version_ = minor_version;
}

void LoadConfiguration::global_flags_clear(uint32_t global_flags_clear) {
  this->global_flags_clear_ = global_flags_clear;
}

void LoadConfiguration::global_flags_set(uint32_t global_flags_set) {
  this->global_flags_set_ = global_flags_set;
}

void LoadConfiguration::critical_section_default_timeout(uint32_t critical_section_default_timeout) {
  this->critical_section_default_timeout_ = critical_section_default_timeout;
}

void LoadConfiguration::decommit_free_block_threshold(uint64_t decommit_free_block_threshold) {
  this->decommit_free_block_threshold_ = decommit_free_block_threshold;
}

void LoadConfiguration::decommit_total_free_threshold(uint64_t decommit_total_free_threshold) {
  this->decommit_total_free_threshold_ = decommit_total_free_threshold;
}

void LoadConfiguration::lock_prefix_table(uint64_t lock_prefix_table) {
  this->lock_prefix_table_ = lock_prefix_table;
}

void LoadConfiguration::maximum_allocation_size(uint64_t maximum_allocation_size) {
  this->maximum_allocation_size_ = maximum_allocation_size;
}

void LoadConfiguration::virtual_memory_threshold(uint64_t virtual_memory_threshold) {
  this->virtual_memory_threshold_ = virtual_memory_threshold;
}

void LoadConfiguration::process_affinity_mask(uint64_t process_affinity_mask) {
  this->process_affinity_mask_ = process_affinity_mask;
}

void LoadConfiguration::process_heap_flags(uint32_t process_heap_flagsid) {
  this->process_heap_flags_ = process_heap_flagsid;
}

void LoadConfiguration::csd_version(uint16_t csd_version) {
  this->csd_version_ = csd_version;
}

void LoadConfiguration::reserved1(uint16_t reserved1) {
  this->reserved1_ = reserved1;
}

void LoadConfiguration::editlist(uint32_t editlist) {
  this->editlist_ = editlist;
}

void LoadConfiguration::security_cookie(uint32_t security_cookie) {
  this->security_cookie_ = security_cookie;
}

void LoadConfiguration::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfiguration::operator==(const LoadConfiguration& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadConfiguration::operator!=(const LoadConfiguration& rhs) const {
  return not (*this == rhs);
}

std::ostream& LoadConfiguration::print(std::ostream& os) const {
  os << std::hex << std::left << std::showbase;

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Version:"                          << std::hex << to_string(this->version()) << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Characteristics:"                  << std::hex << this->characteristics()    << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Timedatestamp:"                    << std::dec << this->timedatestamp()      << std::endl;

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Major version:"                    << std::dec << this->major_version() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Minor version:"                    << std::dec << this->minor_version() << std::endl;

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Global flags clear:"               << std::hex << this->global_flags_clear() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Global flags set:"                 << std::hex << this->global_flags_set()   << std::endl;

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Critical section default timeout:" << std::dec << this->critical_section_default_timeout() << std::endl;

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Decommit free block threshold:"    << std::hex << this->decommit_free_block_threshold() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Decommit total free threshold:"    << std::hex << this->decommit_total_free_threshold() << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Lock prefix table:"                << std::hex << this->lock_prefix_table()             << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Maximum allocation size:"          << std::hex << this->maximum_allocation_size()       << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Virtual memory threshold:"         << std::hex << this->virtual_memory_threshold()      << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Process affinity mask:"            << std::hex << this->process_affinity_mask()         << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Process heap flags:"               << std::hex << this->process_heap_flags()            << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "CSD Version:"                      << std::hex << this->csd_version()                   << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Reserved 1:"                       << std::hex << this->reserved1()                     << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Edit list:"                        << std::hex << this->editlist()                      << std::endl;
  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Security cookie:"                  << std::hex << this->security_cookie()               << std::endl;
  return os;
}

std::ostream& operator<<(std::ostream& os, const LoadConfiguration& config) {
  return config.print(os);
}


} // namespace PE
} // namespace LIEF

