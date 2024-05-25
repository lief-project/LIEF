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
#include "LIEF/PE/debug/Pogo.hpp"
#include "LIEF/Visitor.hpp"
#include "frozen.hpp"
#include <spdlog/fmt/fmt.h>

namespace LIEF {
namespace PE {

Pogo::Pogo() {
  type_ = Debug::TYPES::POGO;
}

Pogo::Pogo(const details::pe_debug& debug, SIGNATURES sig) :
  Debug{debug},
  sig_{sig}
{}

void Pogo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Pogo& entry) {
  os << static_cast<const Debug&>(entry)
     << fmt::format("[POGO] Signature:    {}\n", to_string(entry.signature()));

  for (const PogoEntry& pentry : entry.entries()) {
    os << ' ' << pentry << '\n';
  }
  return os;
}

const char* to_string(Pogo::SIGNATURES e) {
  CONST_MAP(Pogo::SIGNATURES, const char*, 4) Enum2Str {
    { Pogo::SIGNATURES::UNKNOWN, "UNKNOWN" },
    { Pogo::SIGNATURES::ZERO,    "ZERO"    },
    { Pogo::SIGNATURES::LCTG,    "LCTG"    },
    { Pogo::SIGNATURES::PGI,     "PGI"     },
  };

  if (const auto it = Enum2Str.find(e); it != Enum2Str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

} // namespace PE
} // namespace LIEF
