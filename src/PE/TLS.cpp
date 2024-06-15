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
#include <algorithm>
#include "LIEF/Visitor.hpp"

#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/Section.hpp"
#include "PE/Structures.hpp"

#include "spdlog/fmt/fmt.h"

namespace LIEF {
namespace PE {

TLS::TLS(const details::pe32_tls& header) :
  va_rawdata_{header.RawDataStartVA, header.RawDataEndVA},
  addressof_index_{header.AddressOfIndex},
  addressof_callbacks_{header.AddressOfCallback},
  sizeof_zero_fill_{header.SizeOfZeroFill},
  characteristics_{header.Characteristics}
{}

TLS::TLS(const details::pe64_tls& header) :
  va_rawdata_{header.RawDataStartVA, header.RawDataEndVA},
  addressof_index_{header.AddressOfIndex},
  addressof_callbacks_{header.AddressOfCallback},
  sizeof_zero_fill_{header.SizeOfZeroFill},
  characteristics_{header.Characteristics}
{}

void TLS::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const TLS& entry) {

  os << fmt::format("Address of index:     0x{:x}\n", entry.addressof_index())
     << fmt::format("Address of callbacks: 0x{:x}\n", entry.addressof_callbacks())
     << fmt::format("Address of raw data:  0x{:x}-0x{:x}\n",
                    entry.addressof_raw_data().first,
                    entry.addressof_raw_data().second)
     << fmt::format("Size of zerofill:     0x{:x}\n", entry.sizeof_zero_fill());

  if (const Section* section = entry.section()) {
    os << fmt::format("Section:              '{}'\n", section->name());
  }

  if (const std::vector<uint64_t>& cbk = entry.callbacks(); !cbk.empty()) {
    std::vector<std::string> formated;
    formated.reserve(cbk.size());
    std::transform(cbk.begin(), cbk.end(), std::back_inserter(formated),
                   [] (uint64_t addr) { return fmt::format("0x{:04x}", addr); });

    os << fmt::format("Callbacks:            {}", fmt::join(formated, ", "));
  }

  return os;
}

} // namespace PE
} // namespace LIEF

