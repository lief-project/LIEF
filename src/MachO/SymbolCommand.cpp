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
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/SymbolCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

SymbolCommand::SymbolCommand() = default;
SymbolCommand& SymbolCommand::operator=(const SymbolCommand&) = default;
SymbolCommand::SymbolCommand(const SymbolCommand&) = default;
SymbolCommand::~SymbolCommand() = default;

SymbolCommand::SymbolCommand(const details::symtab_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  symbols_offset_{cmd.symoff},
  nb_symbols_{cmd.nsyms},
  strings_offset_{cmd.stroff},
  strings_size_{cmd.strsize}
{}

SymbolCommand* SymbolCommand::clone() const {
  return new SymbolCommand(*this);
}

uint32_t SymbolCommand::symbol_offset() const {
  return symbols_offset_;
}

uint32_t SymbolCommand::numberof_symbols() const {
  return nb_symbols_;
}

uint32_t SymbolCommand::strings_offset() const {
  return strings_offset_;
}

uint32_t SymbolCommand::strings_size() const {
  return strings_size_;
}

void SymbolCommand::symbol_offset(uint32_t offset) {
  symbols_offset_ = offset;
}

void SymbolCommand::numberof_symbols(uint32_t nb) {
  nb_symbols_ = nb;
}

void SymbolCommand::strings_offset(uint32_t offset) {
  strings_offset_ = offset;
}

void SymbolCommand::strings_size(uint32_t size) {
  strings_size_ = size;
}

void SymbolCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool SymbolCommand::operator==(const SymbolCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolCommand::operator!=(const SymbolCommand& rhs) const {
  return !(*this == rhs);
}

bool SymbolCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_SYMTAB;
}

std::ostream& SymbolCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  return os;
}


}
}
