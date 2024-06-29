/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_PE_LOAD_CONFIGURATION_H
#define LIEF_PE_LOAD_CONFIGURATION_H
#include <ostream>
#include <cstdint>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration;
}

//! Class that represents the default PE's ``LoadConfiguration``
//!
//! It's the base class for any future versions of the structure
class LIEF_API LoadConfiguration : public Object {
  public:
  enum class VERSION {
    UNKNOWN = 0,
    SEH,
    WIN_8_1,
    WIN_10_0_9879,
    WIN_10_0_14286,
    WIN_10_0_14383,
    WIN_10_0_14901,
    WIN_10_0_15002,
    WIN_10_0_16237,
    WIN_10_0_18362,
    WIN_10_0_19534,
    WIN_10_0_MSVC_2019,
    WIN_10_0_MSVC_2019_16,
  };

  static constexpr VERSION WIN_VERSION = VERSION::UNKNOWN;

  LoadConfiguration() = default;

  template<class T>
  LIEF_LOCAL LoadConfiguration(const details::load_configuration<T>& header);

  LoadConfiguration& operator=(const LoadConfiguration&) = default;
  LoadConfiguration(const LoadConfiguration&) = default;

  //! (SDK) Version of the structure
  virtual VERSION version() const {
    return WIN_VERSION;
  }

  //! Characteristics of the structure
  //! It usually holds its size
  //!
  //! @see @link version LoadConfiguration::version@endlink
  uint32_t characteristics() const {
    return characteristics_;
  }

  //! Size of the current structure which is an alias for characteristics
  uint32_t size() const {
    return characteristics_;
  }

  //! Date and time stamp value
  uint32_t timedatestamp() const {
    return timedatestamp_;
  }

  //! Major Version
  uint16_t major_version() const {
    return major_version_;
  }

  //! Minor version
  uint16_t minor_version() const {
    return minor_version_;
  }

  //! The global loader flags to clear for
  //! this process as the loader start the process.
  uint32_t global_flags_clear() const {
    return global_flags_clear_;
  }

  //! The global loader flags to set for
  //! this process as the loader starts the process.
  uint32_t global_flags_set() const {
    return global_flags_set_;
  }

  //! The default timeout value to use for
  //! this process’s critical sections that are abandoned.
  uint32_t critical_section_default_timeout() const {
    return critical_section_default_timeout_;
  }

  //! Memory that must be freed before
  //! it is returned to the system, in bytes.
  uint64_t decommit_free_block_threshold() const {
    return decommit_free_block_threshold_;
  }

  //! Total amount of free memory, in
  //! bytes.
  uint64_t decommit_total_free_threshold() const {
    return decommit_total_free_threshold_;
  }

  //! The VA of a list of
  //! addresses where the LOCK prefix
  //! is used so that they can be replaced with NOP on single
  //! processor machines.
  //!
  //! @warning For ``x86`` only
  uint64_t lock_prefix_table() const {
    return lock_prefix_table_;
  }

  //! Maximum allocation size, in bytes.
  uint64_t maximum_allocation_size() const {
    return maximum_allocation_size_;
  }

  //! Maximum virtual memory size, in bytes.
  uint64_t virtual_memory_threshold() const {
    return virtual_memory_threshold_;
  }

  //! Setting this field to a non-zero value is equivalent to calling
  //! ``SetProcessAffinityMask`` with this value during process startup (.exe only)
  uint64_t process_affinity_mask() const {
    return process_affinity_mask_;
  }

  //! Process heap flags that correspond to the first argument of the
  //! ``HeapCreate`` function. These flags apply to the process heap that is
  //! created during process startup.
  uint32_t process_heap_flags() const {
    return process_heap_flags_;
  }

  //! The service pack version identifier.
  uint16_t csd_version() const {
    return csd_version_;
  }

  //! Must be zero.
  uint16_t reserved1() const {
    return reserved1_;
  }

  //! Alias for reserved1.
  //!
  //! On recent the version of the structure, Microsoft renamed reserved1 to DependentLoadFlags
  uint16_t dependent_load_flags() const {
    return reserved1_;
  }

  //! Reserved for use by the system.
  uint32_t editlist() const {
    return editlist_;
  }

  //! A pointer to a cookie that is used by Visual C++ or GS
  //! implementation.
  uint32_t security_cookie() const {
    return security_cookie_;
  }


  void characteristics(uint32_t characteristics) {
    characteristics_ = characteristics;
  }

  void timedatestamp(uint32_t timedatestamp) {
    timedatestamp_ = timedatestamp;
  }

  void major_version(uint16_t major_version) {
    major_version_ = major_version;
  }

  void minor_version(uint16_t minor_version) {
    minor_version_ = minor_version;
  }

  void global_flags_clear(uint32_t global_flags_clear) {
    global_flags_clear_ = global_flags_clear;
  }

  void global_flags_set(uint32_t global_flags_set) {
    global_flags_set_ = global_flags_set;
  }

  void critical_section_default_timeout(uint32_t critical_section_default_timeout) {
    critical_section_default_timeout_ = critical_section_default_timeout;
  }

  void decommit_free_block_threshold(uint64_t decommit_free_block_threshold) {
    decommit_free_block_threshold_ = decommit_free_block_threshold;
  }

  void decommit_total_free_threshold(uint64_t decommit_total_free_threshold) {
    decommit_total_free_threshold_ = decommit_total_free_threshold;
  }

  void lock_prefix_table(uint64_t lock_prefix_table) {
    lock_prefix_table_ = lock_prefix_table;
  }

  void maximum_allocation_size(uint64_t maximum_allocation_size) {
    maximum_allocation_size_ = maximum_allocation_size;
  }

  void virtual_memory_threshold(uint64_t virtual_memory_threshold) {
    virtual_memory_threshold_ = virtual_memory_threshold;
  }

  void process_affinity_mask(uint64_t process_affinity_mask) {
    process_affinity_mask_ = process_affinity_mask;
  }

  void process_heap_flags(uint32_t process_heap_flagsid) {
    process_heap_flags_ = process_heap_flagsid;
  }

  void csd_version(uint16_t csd_version) {
    csd_version_ = csd_version;
  }

  void reserved1(uint16_t reserved1) {
    reserved1_ = reserved1;
  }

  void dependent_load_flags(uint16_t flags) {
    reserved1(flags);
  }

  void editlist(uint32_t editlist) {
    editlist_ = editlist;
  }

  void security_cookie(uint32_t security_cookie) {
    security_cookie_ = security_cookie;
  }

  ~LoadConfiguration() override = default;

  static bool classof(const LoadConfiguration* /*config*/) {
    // This is the base class, thus all the other
    // classes can be safely casted into this one.
    return true;
  }

  template<class T>
  static const T* cast(const LoadConfiguration* config) {
    if (config->version() >= T::WIN_VERSION) {
      return static_cast<const T*>(config);
    }
    return nullptr;
  }

  void accept(Visitor& visitor) const override;

  virtual std::ostream& print(std::ostream& os) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const LoadConfiguration& config);

  protected:
  uint32_t characteristics_ = 0; // also named size
  uint32_t timedatestamp_ = 0;

  uint16_t major_version_ = 0;
  uint16_t minor_version_ = 0;

  uint32_t global_flags_clear_ = 0;
  uint32_t global_flags_set_ = 0;

  uint32_t critical_section_default_timeout_ = 0;

  uint64_t decommit_free_block_threshold_ = 0;
  uint64_t decommit_total_free_threshold_ = 0;

  uint64_t lock_prefix_table_ = 0;
  uint64_t maximum_allocation_size_ = 0;
  uint64_t virtual_memory_threshold_ = 0;
  uint64_t process_affinity_mask_ = 0;
  uint32_t process_heap_flags_ = 0;
  uint16_t csd_version_ = 0;
  uint16_t reserved1_ = 0;  // named DependentLoadFlags in recent headers
  uint64_t editlist_ = 0;
  uint64_t security_cookie_ = 0;
};

LIEF_API const char* to_string(LoadConfiguration::VERSION e);

}
}

#endif
