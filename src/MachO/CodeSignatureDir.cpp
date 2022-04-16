/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <numeric>
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/CodeSignatureDir.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

CodeSignatureDir::CodeSignatureDir() = default;
CodeSignatureDir& CodeSignatureDir::operator=(const CodeSignatureDir&) = default;
CodeSignatureDir::CodeSignatureDir(const CodeSignatureDir&) = default;
CodeSignatureDir::~CodeSignatureDir() = default;

CodeSignatureDir::CodeSignatureDir(const details::linkedit_data_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  data_offset_{cmd.dataoff},
  data_size_{cmd.datasize}
{}


CodeSignatureDir* CodeSignatureDir::clone() const {
  return new CodeSignatureDir(*this);
}

void CodeSignatureDir::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool CodeSignatureDir::operator==(const CodeSignatureDir& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CodeSignatureDir::operator!=(const CodeSignatureDir& rhs) const {
  return !(*this == rhs);
}

bool CodeSignatureDir::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_DYLIB_CODE_SIGN_DRS;
}


std::ostream& CodeSignatureDir::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::left;
  os << std::endl;
  os << "Code Signature Dir:" << std::endl;
  os << std::setw(8) << "Offset" << ": 0x" << data_offset() << std::endl;
  os << std::setw(8) << "Size"   << ": 0x" << data_size()   << std::endl;
  return os;
}


}
}
