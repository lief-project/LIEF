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
#include <LIEF/PE/debug/CodeView.hpp>
#include "LIEF/Visitor.hpp"
#include "spdlog/fmt/fmt.h"
#include "frozen.hpp"

namespace LIEF {
namespace PE {

CodeView::CodeView(const details::pe_debug& debug, SIGNATURES sig) :
  Debug{debug},
  sig_{sig}
{}

void CodeView::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const CodeView& entry) {
  os << static_cast<const Debug&>(entry)
     << fmt::format("[CV] Signature: {}", to_string(entry.signature()))
  ;
  return os;
}

const char* to_string(CodeView::SIGNATURES e) {
  CONST_MAP(CodeView::SIGNATURES, const char*, 5) Enum2Str {
    { CodeView::SIGNATURES::UNKNOWN, "UNKNOWN" },
    { CodeView::SIGNATURES::PDB_70,  "PDB_70"  },
    { CodeView::SIGNATURES::PDB_20,  "PDB_20"  },
    { CodeView::SIGNATURES::CV_50,   "CV_50"   },
    { CodeView::SIGNATURES::CV_41,   "CV_41"   },
  };
  if (const auto it = Enum2Str.find(e); it != Enum2Str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

}
}
