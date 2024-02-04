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

#include "LIEF/PE/CodeIntegrity.hpp"
#include "LIEF/Visitor.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

CodeIntegrity::CodeIntegrity(const details::pe_code_integrity& header) :
  flags_{header.Flags},
  catalog_{header.Catalog},
  catalog_offset_{header.CatalogOffset},
  reserved_{header.Reserved}
{}

void CodeIntegrity::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const CodeIntegrity& entry) {
  os << fmt::format("Flags          0x{:x}\n", entry.flags())
     << fmt::format("Catalog        0x{:x}\n", entry.catalog())
     << fmt::format("Catalog offset 0x{:x}\n", entry.catalog_offset())
     << fmt::format("Reserved       0x{:x}\n", entry.reserved());
  return os;
}

}
}
