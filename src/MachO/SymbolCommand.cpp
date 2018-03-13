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
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/SymbolCommand.hpp"

namespace LIEF {
namespace MachO {

SymbolCommand::SymbolCommand(void) = default;
SymbolCommand& SymbolCommand::operator=(const SymbolCommand&) = default;
SymbolCommand::SymbolCommand(const SymbolCommand&) = default;
SymbolCommand::~SymbolCommand(void) = default;

SymbolCommand::SymbolCommand(const symtab_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  symbolOffset_{cmd->symoff},
  numberOfSymbols_{cmd->nsyms},
  stringsOffset_{cmd->stroff},
  stringsSize_{cmd->strsize}
{}

uint32_t SymbolCommand::symbol_offset(void) const {
  return this->symbolOffset_;
}

uint32_t SymbolCommand::numberof_symbols(void) const {
  return this->numberOfSymbols_;
}

uint32_t SymbolCommand::strings_offset(void) const {
  return this->stringsOffset_;
}

uint32_t SymbolCommand::strings_size(void) const {
  return this->stringsSize_;
}

void SymbolCommand::symbol_offset(uint32_t offset) {
  this->symbolOffset_ = offset;
}

void SymbolCommand::numberof_symbol(uint32_t nb) {
  this->numberOfSymbols_ = nb;
}

void SymbolCommand::strings_offset(uint32_t offset) {
  this->stringsOffset_ = offset;
}

void SymbolCommand::strings_size(uint32_t size) {
  this->stringsSize_ = size;
}

void SymbolCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool SymbolCommand::operator==(const SymbolCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolCommand::operator!=(const SymbolCommand& rhs) const {
  return not (*this == rhs);
}

std::ostream& SymbolCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  return os;
}


}
}
