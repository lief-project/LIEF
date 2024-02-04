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
#include <spdlog/fmt/fmt.h>
#include <ostream>
#include <array>
#include <algorithm>

#include "LIEF/Visitor.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV1.hpp"

#include "fmt_formatter.hpp"
#include "PE/Structures.hpp"
#include "frozen.hpp"

FMT_FORMATTER(LIEF::PE::LoadConfigurationV1::IMAGE_GUARD, LIEF::PE::to_string);

namespace LIEF {
namespace PE {

static constexpr std::array IMAGE_GUARD_LIST = {
  LoadConfigurationV1::IMAGE_GUARD::CF_INSTRUMENTED,
  LoadConfigurationV1::IMAGE_GUARD::CFW_INSTRUMENTED,
  LoadConfigurationV1::IMAGE_GUARD::CF_FUNCTION_TABLE_PRESENT,
  LoadConfigurationV1::IMAGE_GUARD::SECURITY_COOKIE_UNUSED,
  LoadConfigurationV1::IMAGE_GUARD::PROTECT_DELAYLOAD_IAT,
  LoadConfigurationV1::IMAGE_GUARD::DELAYLOAD_IAT_IN_ITS_OWN_SECTION,
  LoadConfigurationV1::IMAGE_GUARD::CF_EXPORT_SUPPRESSION_INFO_PRESENT,
  LoadConfigurationV1::IMAGE_GUARD::CF_ENABLE_EXPORT_SUPPRESSION,
  LoadConfigurationV1::IMAGE_GUARD::CF_LONGJUMP_TABLE_PRESENT,
  LoadConfigurationV1::IMAGE_GUARD::RF_INSTRUMENTED,
  LoadConfigurationV1::IMAGE_GUARD::RF_ENABLE,
  LoadConfigurationV1::IMAGE_GUARD::RF_STRICT,
  LoadConfigurationV1::IMAGE_GUARD::RETPOLINE_PRESENT,
  LoadConfigurationV1::IMAGE_GUARD::EH_CONTINUATION_TABLE_PRESENT,
};

template<class T>
LoadConfigurationV1::LoadConfigurationV1(const details::load_configuration_v1<T>& header) :
  LoadConfigurationV0{reinterpret_cast<const details::load_configuration_v0<T>&>(header)},
  guard_cf_check_function_pointer_{header.GuardCFCheckFunctionPointer},
  guard_cf_dispatch_function_pointer_{header.GuardCFDispatchFunctionPointer},
  guard_cf_function_table_{header.GuardCFFunctionTable},
  guard_cf_function_count_{header.GuardCFFunctionCount},
  flags_{static_cast<IMAGE_GUARD>(header.GuardFlags)}
{}

std::vector<LoadConfigurationV1::IMAGE_GUARD> LoadConfigurationV1::guard_cf_flags_list() const {
  std::vector<IMAGE_GUARD> flags;
  std::copy_if(std::begin(IMAGE_GUARD_LIST), std::end(IMAGE_GUARD_LIST),
               std::back_inserter(flags),
               [this] (IMAGE_GUARD f) { return has(f); });
  return flags;
}

void LoadConfigurationV1::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadConfigurationV1::has(IMAGE_GUARD flag) const {
  return (guard_flags() & flag) != IMAGE_GUARD::NONE;
}

std::ostream& LoadConfigurationV1::print(std::ostream& os) const {
  LoadConfigurationV0::print(os);
  os << "LoadConfigurationV1:\n"
     << fmt::format("  GCF check function pointer     0x{:08x}\n", guard_cf_check_function_pointer())
     << fmt::format("  GCF dispatch function pointer  0x{:08x}\n", guard_cf_dispatch_function_pointer())
     << fmt::format("  GCF function table             0x{:08x}\n", guard_cf_function_table())
     << fmt::format("  GCF Function count             0x{:08x}\n", guard_cf_function_count())
     << fmt::format("  Guard Flags                    {}\n", guard_cf_flags_list());
  return os;
}

const char* to_string(LoadConfigurationV1::IMAGE_GUARD e) {
  #define ENTRY(X) std::pair(LoadConfigurationV1::IMAGE_GUARD::X, #X)
  STRING_MAP enums2str {
    ENTRY(NONE),
    ENTRY(CF_INSTRUMENTED),
    ENTRY(CFW_INSTRUMENTED),
    ENTRY(CF_FUNCTION_TABLE_PRESENT),
    ENTRY(SECURITY_COOKIE_UNUSED),
    ENTRY(PROTECT_DELAYLOAD_IAT),
    ENTRY(DELAYLOAD_IAT_IN_ITS_OWN_SECTION),
    ENTRY(CF_EXPORT_SUPPRESSION_INFO_PRESENT),
    ENTRY(CF_ENABLE_EXPORT_SUPPRESSION),
    ENTRY(CF_LONGJUMP_TABLE_PRESENT),
    ENTRY(RF_INSTRUMENTED),
    ENTRY(RF_ENABLE),
    ENTRY(RF_STRICT),
    ENTRY(RETPOLINE_PRESENT),
    ENTRY(EH_CONTINUATION_TABLE_PRESENT),
  };
  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }

  return "NONE";
}

template
LoadConfigurationV1::LoadConfigurationV1(const details::load_configuration_v1<uint32_t>& header);
template
LoadConfigurationV1::LoadConfigurationV1(const details::load_configuration_v1<uint64_t>& header);


} // namespace PE
} // namespace LIEF

