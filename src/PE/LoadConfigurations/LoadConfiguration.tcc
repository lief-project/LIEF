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

#include "LIEF/PE/LoadConfigurations.hpp"

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


} // namespace PE
} // namespace LIEF

