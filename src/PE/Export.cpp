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
#include "LIEF/Visitor.hpp"

#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/ExportEntry.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

Export::Export(const details::pe_export_directory_table& header) :
  export_flags_{header.ExportFlags},
  timestamp_{header.Timestamp},
  major_version_{header.MajorVersion},
  minor_version_{header.MinorVersion},
  ordinal_base_{header.OrdinalBase}
{}

void Export::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Export& exp) {
  os << std::hex;
  os << std::left;
  os << exp.name() << '\n';
  for (const ExportEntry& entry : exp.entries()) {
    os << "  " << entry << '\n';
  }
  return os;
}

}
}
