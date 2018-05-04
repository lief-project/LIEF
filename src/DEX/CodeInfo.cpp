
/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

namespace LIEF {
namespace DEX {

CodeInfo::CodeInfo(const CodeInfo&) = default;
CodeInfo& CodeInfo::operator=(const CodeInfo&) = default;

CodeInfo::CodeInfo(const code_item* codeitem) :
  nb_registers_{codeitem->registers_size},
  args_input_sizes_{codeitem->ins_size},
  output_sizes_{codeitem->outs_size}
{}

CodeInfo::CodeInfo(void) :
  nb_registers_{0},
  args_input_sizes_{0},
  output_sizes_{0}
{}


void CodeInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CodeInfo::operator==(const CodeInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CodeInfo::operator!=(const CodeInfo& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const CodeInfo& cinfo) {

  return os;
}

CodeInfo::~CodeInfo(void) = default;

}
}
