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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V1_H
#define LIEF_PE_LOAD_CONFIGURATION_V1_H
#include <ostream>
#include <vector>

#include "LIEF/enums.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV0.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v1;
}
//! LoadConfiguration enhanced with Control Flow Guard
//!
//! This structure is available from Windows 8.1
class LIEF_API LoadConfigurationV1 : public LoadConfigurationV0 {
  public:
  static constexpr VERSION WIN_VERSION = VERSION::WIN_8_1;

  enum class IMAGE_GUARD : uint32_t {
    NONE                               = 0x00000000,
    CF_INSTRUMENTED                    = 0x00000100, /**< Module performs control flow integrity checks using system-supplied support */
    CFW_INSTRUMENTED                   = 0x00000200, /**< Module performs control flow and write integrity checks */
    CF_FUNCTION_TABLE_PRESENT          = 0x00000400, /**< Module contains valid control flow target metadata */
    SECURITY_COOKIE_UNUSED             = 0x00000800, /**< Module does not make use of the /GS security cookie */
    PROTECT_DELAYLOAD_IAT              = 0x00001000, /**< Module supports read only delay load IAT */
    DELAYLOAD_IAT_IN_ITS_OWN_SECTION   = 0x00002000, /**< Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected */
    CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000, /**< Module contains suppressed export information. This also infers that the address taken taken IAT table is also present in the load config. */
    CF_ENABLE_EXPORT_SUPPRESSION       = 0x00008000, /**< Module enables suppression of exports */
    CF_LONGJUMP_TABLE_PRESENT          = 0x00010000, /**< Module contains longjmp target information */
    RF_INSTRUMENTED                    = 0x00020000, /**< Module contains return flow instrumentation and metadata */
    RF_ENABLE                          = 0x00040000, /**< Module requests that the OS enable return flow protection */
    RF_STRICT                          = 0x00080000, /**< Module requests that the OS enable return flow protection in strict mode */
    RETPOLINE_PRESENT                  = 0x00100000, /**< Module was built with retpoline support */
    EH_CONTINUATION_TABLE_PRESENT      = 0x00200000, /**< Module contains EH continuation target information */
  };

  LoadConfigurationV1() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV1(const details::load_configuration_v1<T>& header);

  LoadConfigurationV1& operator=(const LoadConfigurationV1&) = default;
  LoadConfigurationV1(const LoadConfigurationV1&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  //! @brief The VA where Control Flow Guard check-function pointer is stored.
  uint64_t guard_cf_check_function_pointer() const {
    return guard_cf_check_function_pointer_;
  }

  //! @brief The VA where Control Flow Guard dispatch-function pointer is stored.
  uint64_t guard_cf_dispatch_function_pointer() const {
    return guard_cf_dispatch_function_pointer_;
  }

  //! @brief The VA of the sorted table of RVAs of each Control Flow Guard
  //! function in the image.
  uint64_t guard_cf_function_table() const {
    return guard_cf_function_table_;
  }

  //! @brief The count of unique RVAs in the
  //! LoadConfigurationV1::guard_cf_function_table.
  uint64_t guard_cf_function_count() const {
    return guard_cf_function_count_;
  }

  //! @brief Control Flow Guard related flags.
  IMAGE_GUARD guard_flags() const {
    return flags_;
  }

  //! @brief Check if the given flag is present in LoadConfigurationV1::guard_flags
  bool has(IMAGE_GUARD flag) const;

  //! @brief LoadConfigurationV1::guard_flags as a list of LIEF::PE::GUARD_CF_FLAGS
  std::vector<IMAGE_GUARD> guard_cf_flags_list() const;

  void guard_cf_check_function_pointer(uint64_t check_pointer) {
    guard_cf_check_function_pointer_ = check_pointer;
  }
  void guard_cf_dispatch_function_pointer(uint64_t dispatch_pointer) {
    guard_cf_dispatch_function_pointer_ = dispatch_pointer;
  }
  void guard_cf_function_table(uint64_t guard_cf_function_table) {
    guard_cf_function_table_ = guard_cf_function_table;
  }
  void guard_cf_function_count(uint64_t guard_cf_function_count) {
    guard_cf_function_count_ = guard_cf_function_count;
  }
  void guard_flags(IMAGE_GUARD flags) {
    flags_ = flags;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV1() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_cf_check_function_pointer_ = 0;
  uint64_t guard_cf_dispatch_function_pointer_ = 0;
  uint64_t guard_cf_function_table_ = 0;
  uint64_t guard_cf_function_count_ = 0;
  IMAGE_GUARD flags_ = IMAGE_GUARD::NONE;
};

LIEF_API const char* to_string(LoadConfigurationV1::IMAGE_GUARD e);

}
}

ENABLE_BITMASK_OPERATORS(LIEF::PE::LoadConfigurationV1::IMAGE_GUARD);

#endif
