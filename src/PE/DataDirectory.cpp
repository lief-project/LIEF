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

DataDirectory::~DataDirectory() = default;
DataDirectory::DataDirectory() = default;

DataDirectory::DataDirectory(const DataDirectory& other) = default;
DataDirectory& DataDirectory::operator=(const DataDirectory& other) = default;

DataDirectory::DataDirectory(DataDirectory&& other) = default;
DataDirectory& DataDirectory::operator=(DataDirectory&& other) = default;

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
  CONST_MAP(DataDirectory::TYPES, const char*, 17) enumStrings {
    { DataDirectory::TYPES::EXPORT_TABLE,            "EXPORT_TABLE" },
    { DataDirectory::TYPES::IMPORT_TABLE,            "IMPORT_TABLE" },
    { DataDirectory::TYPES::RESOURCE_TABLE,          "RESOURCE_TABLE" },
    { DataDirectory::TYPES::EXCEPTION_TABLE,         "EXCEPTION_TABLE" },
    { DataDirectory::TYPES::CERTIFICATE_TABLE,       "CERTIFICATE_TABLE" },
    { DataDirectory::TYPES::BASE_RELOCATION_TABLE,   "BASE_RELOCATION_TABLE" },
    { DataDirectory::TYPES::DEBUG,                   "DEBUG" },
    { DataDirectory::TYPES::ARCHITECTURE,            "ARCHITECTURE" },
    { DataDirectory::TYPES::GLOBAL_PTR,              "GLOBAL_PTR" },
    { DataDirectory::TYPES::TLS_TABLE,               "TLS_TABLE" },
    { DataDirectory::TYPES::LOAD_CONFIG_TABLE,       "LOAD_CONFIG_TABLE" },
    { DataDirectory::TYPES::BOUND_IMPORT,            "BOUND_IMPORT" },
    { DataDirectory::TYPES::IAT,                     "IAT" },
    { DataDirectory::TYPES::DELAY_IMPORT_DESCRIPTOR, "DELAY_IMPORT_DESCRIPTOR" },
    { DataDirectory::TYPES::CLR_RUNTIME_HEADER,      "CLR_RUNTIME_HEADER" },
    { DataDirectory::TYPES::RESERVED,                "RESERVED" },

    { DataDirectory::TYPES::UNKNOWN,                 "UNKNOWN" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}


}
}
