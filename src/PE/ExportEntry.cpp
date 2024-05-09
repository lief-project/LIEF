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
#include <iomanip>

#include "LIEF/Visitor.hpp"
#include "LIEF/PE/ExportEntry.hpp"

namespace LIEF {
namespace PE {
ExportEntry::ExportEntry(uint32_t address, bool is_extern, uint16_t ordinal, uint32_t function_rva) :
  function_rva_{function_rva},
  ordinal_{ordinal},
  address_{address},
  is_extern_{is_extern}
{}

void ExportEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const ExportEntry::forward_information_t& info) {
  os << info.library << "." << info.function;
  return os;
}

std::ostream& operator<<(std::ostream& os, const ExportEntry& export_entry) {
  os << std::hex;
  os << std::left;
  std::string name = export_entry.name();
  if (name.size() > 30) {
    name = name.substr(0, 27) + "... ";
  }
  os << std::setw(33) << name;
  os << std::setw(5)  << export_entry.ordinal();

  if (!export_entry.is_extern()) {
    os << std::setw(10) << export_entry.address();
  } else {
    os << std::setw(10) << "[Extern]";
  }

  if (export_entry.is_forwarded()) {
    os << " " << export_entry.forward_information();
  }
  return os;
}

}
}
