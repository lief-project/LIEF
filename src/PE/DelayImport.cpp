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
#include <utility>
#include <spdlog/fmt/fmt.h>

#include "LIEF/Visitor.hpp"

#include "LIEF/PE/DelayImport.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

void DelayImport::swap(DelayImport& other) {
  std::swap(attribute_,   other.attribute_);
  std::swap(name_,        other.name_);
  std::swap(handle_,      other.handle_);
  std::swap(iat_,         other.iat_);
  std::swap(names_table_, other.names_table_);
  std::swap(bound_iat_,   other.bound_iat_);
  std::swap(unload_iat_,  other.unload_iat_);
  std::swap(timestamp_,   other.timestamp_);
  std::swap(entries_,     other.entries_);
  std::swap(type_,        other.type_);
}

DelayImport::DelayImport(const details::delay_imports& import, PE_TYPE type) :
  attribute_{import.attribute},
  handle_{import.handle},
  iat_{import.iat},
  names_table_{import.name_table},
  bound_iat_{import.bound_iat},
  unload_iat_{import.unload_iat},
  timestamp_{import.timestamp},
  type_{type}
{}

void DelayImport::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const DelayImport& entry) {
  os << fmt::format("{:<20}: #{} imports", entry.name(), entry.entries().size());
  return os;
}
}
}
