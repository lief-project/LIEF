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
#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"
#include "fmt_formatter.hpp"

#include "frozen.hpp"

FMT_FORMATTER(LIEF::PE::LoadConfiguration::VERSION, LIEF::PE::to_string);

namespace LIEF {
namespace PE {

template<class T>
LoadConfiguration::LoadConfiguration(const details::load_configuration<T>& header) :
  characteristics_{header.Characteristics},
  timedatestamp_{header.TimeDateStamp},
  major_version_{header.MajorVersion},
  minor_version_{header.MinorVersion},
  global_flags_clear_{header.GlobalFlagsClear},
  global_flags_set_{header.GlobalFlagsSet},
  critical_section_default_timeout_{header.CriticalSectionDefaultTimeout},
  decommit_free_block_threshold_{header.DeCommitFreeBlockThreshold},
  decommit_total_free_threshold_{header.DeCommitTotalFreeThreshold},
  lock_prefix_table_{header.LockPrefixTable},
  maximum_allocation_size_{header.MaximumAllocationSize},
  virtual_memory_threshold_{header.VirtualMemoryThreshold},
  process_affinity_mask_{header.ProcessAffinityMask},
  process_heap_flags_{header.ProcessHeapFlags},
  csd_version_{header.CSDVersion},
  reserved1_{header.Reserved1},
  editlist_{header.EditList},
  security_cookie_{header.SecurityCookie}
{}

void LoadConfiguration::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfiguration::print(std::ostream& os) const {
  os << "LoadConfiguration:\n"
     << fmt::format("  Version                          {}\n", version())
     << fmt::format("  Characteristics                  0x{:04x}\n", characteristics())
     << fmt::format("  Timedatestamp                    {}\n", timedatestamp())
     << fmt::format("  Major version                    {}\n", major_version())
     << fmt::format("  Minor version                    {}\n", minor_version())
     << fmt::format("  Global flags clear               0x{:04x}\n", global_flags_clear())
     << fmt::format("  Global flags set                 0x{:04x}\n", global_flags_set())
     << fmt::format("  Critical section default timeout {}\n", critical_section_default_timeout())
     << fmt::format("  Decommit free block threshold    0x{:04x}\n", decommit_free_block_threshold())
     << fmt::format("  Decommit total free threshold    0x{:04x}\n", decommit_total_free_threshold())
     << fmt::format("  Lock prefix table                0x{:04x}\n", lock_prefix_table())
     << fmt::format("  Maximum allocation size          0x{:04x}\n", maximum_allocation_size())
     << fmt::format("  Virtual memory threshold         0x{:04x}\n", virtual_memory_threshold())
     << fmt::format("  Process affinity mask            0x{:04x}\n", process_affinity_mask())
     << fmt::format("  Process heap flags               0x{:04x}\n", process_heap_flags())
     << fmt::format("  CSD Version                      0x{:04x}\n", csd_version())
     << fmt::format("  Reserved 1                       0x{:04x}\n", reserved1())
     << fmt::format("  Edit list                        0x{:04x}\n", editlist())
     << fmt::format("  Security cookie                  0x{:04x}\n", security_cookie())
  ;
  return os;
}

std::ostream& operator<<(std::ostream& os, const LoadConfiguration& config) {
  return config.print(os);
}

const char* to_string(LoadConfiguration::VERSION e) {
  #define ENTRY(X) std::pair(LoadConfiguration::VERSION::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNKNOWN),
    ENTRY(SEH),
    ENTRY(WIN_8_1),
    ENTRY(WIN_10_0_9879),
    ENTRY(WIN_10_0_14286),
    ENTRY(WIN_10_0_14383),
    ENTRY(WIN_10_0_14901),
    ENTRY(WIN_10_0_15002),
    ENTRY(WIN_10_0_16237),
    ENTRY(WIN_10_0_18362),
    ENTRY(WIN_10_0_19534),
    ENTRY(WIN_10_0_MSVC_2019),
    ENTRY(WIN_10_0_MSVC_2019_16),
  };
  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }

  return "UNKNOWN";
}

template
LoadConfiguration::LoadConfiguration(const details::load_configuration<uint32_t>& header);
template
LoadConfiguration::LoadConfiguration(const details::load_configuration<uint64_t>& header);


} // namespace PE
} // namespace LIEF

