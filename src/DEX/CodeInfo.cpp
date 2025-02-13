
/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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

#include "LIEF/DEX/CodeInfo.hpp"
#include "LIEF/DEX/hash.hpp"
#include "DEX/Structures.hpp"

namespace LIEF {
namespace DEX {

CodeInfo::CodeInfo() = default;
CodeInfo::CodeInfo(const CodeInfo&) = default;
CodeInfo& CodeInfo::operator=(const CodeInfo&) = default;

CodeInfo::CodeInfo(const details::code_item& codeitem) :
  nb_registers_{codeitem.registers_size},
  args_input_sizes_{codeitem.ins_size},
  output_sizes_{codeitem.outs_size}
{}


void CodeInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

uint16_t CodeInfo::nb_registers() const {
  return nb_registers_;
}


std::ostream& operator<<(std::ostream& os, const CodeInfo& /*cinfo*/) {

  return os;
}

CodeInfo::~CodeInfo() = default;

}
}
