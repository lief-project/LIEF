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
#include <ostream>

#include "LIEF/Visitor.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "PE/Structures.hpp"

#include "frozen.hpp"

#include <spdlog/fmt/fmt.h>

namespace LIEF {
namespace PE {

DataDirectory::DataDirectory(const details::pe_data_directory& header,
                             DataDirectory::TYPES type) :
  rva_{header.RelativeVirtualAddress},
  size_{header.Size},
  type_{type}
{}

void DataDirectory::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const DataDirectory& entry) {
  os << fmt::format("[{}] 0x{:04x} (0x{:04x} bytes)",
                    to_string(entry.type()), entry.RVA(), entry.size());
  if (const Section* section = entry.section()) {
    os << fmt::format(" - '{}'", section->name());
  }
  os << '\n';
  return os;
}

const char* to_string(DataDirectory::TYPES e) {
  #define ENTRY(X) std::pair(DataDirectory::TYPES::X, #X)
  STRING_MAP enums2str {
    ENTRY(EXPORT_TABLE),
    ENTRY(IMPORT_TABLE),
    ENTRY(RESOURCE_TABLE),
    ENTRY(EXCEPTION_TABLE),
    ENTRY(CERTIFICATE_TABLE),
    ENTRY(BASE_RELOCATION_TABLE),
    ENTRY(DEBUG_DIR),
    ENTRY(ARCHITECTURE),
    ENTRY(GLOBAL_PTR),
    ENTRY(TLS_TABLE),
    ENTRY(LOAD_CONFIG_TABLE),
    ENTRY(BOUND_IMPORT),
    ENTRY(IAT),
    ENTRY(DELAY_IMPORT_DESCRIPTOR),
    ENTRY(CLR_RUNTIME_HEADER),
    ENTRY(RESERVED),
    ENTRY(UNKNOWN),
  };
  #undef ENTRY
  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

}
}
