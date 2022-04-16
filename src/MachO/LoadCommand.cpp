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
#include <iostream>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/EnumToString.hpp"

#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/DyldChainedFixups.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/CodeSignature.hpp"


#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

LoadCommand::LoadCommand() = default;
LoadCommand::~LoadCommand() = default;
LoadCommand::LoadCommand(const LoadCommand& other) = default;

LoadCommand& LoadCommand::operator=(LoadCommand other) {
  swap(other);
  return *this;
}

LoadCommand::LoadCommand(LOAD_COMMAND_TYPES type, uint32_t size) :
  command_{type},
  size_{size}
{}

LoadCommand::LoadCommand(const details::load_command& command) :
  command_{static_cast<LOAD_COMMAND_TYPES>(command.cmd)},
  size_{command.cmdsize}
{}


void LoadCommand::swap(LoadCommand& other) {
  std::swap(original_data_,  other.original_data_);
  std::swap(command_,        other.command_);
  std::swap(size_,           other.size_);
  std::swap(command_offset_, other.command_offset_);
}

LoadCommand* LoadCommand::clone() const {
  return new LoadCommand{*this};
}

LOAD_COMMAND_TYPES LoadCommand::command() const {
  return command_;
}

uint32_t LoadCommand::size() const {
  return size_;
}

const LoadCommand::raw_t& LoadCommand::data() const {
  return original_data_;
}


uint64_t LoadCommand::command_offset() const {
  return command_offset_;
}

void LoadCommand::data(const LoadCommand::raw_t& data) {
  original_data_ = data;
}

void LoadCommand::command(LOAD_COMMAND_TYPES command) {
  command_ = command;
}

void LoadCommand::size(uint32_t size) {
  size_ = size;
}


void LoadCommand::command_offset(uint64_t offset) {
  command_offset_ = offset;
}


void LoadCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool LoadCommand::is_linkedit_data(const LoadCommand& cmd) {
  if (DyldInfo::classof(&cmd))             return true;
  if (DyldExportsTrie::classof(&cmd))      return true;
  if (DyldChainedFixups::classof(&cmd))    return true;
  if (DynamicSymbolCommand::classof(&cmd)) return true;
  if (SegmentSplitInfo::classof(&cmd))     return true;
  if (FunctionStarts::classof(&cmd))       return true;
  if (DataInCode::classof(&cmd))           return true;
  if (SymbolCommand::classof(&cmd))        return true;
  if (CodeSignature::classof(&cmd))        return true;
  return false;
}

bool LoadCommand::operator==(const LoadCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadCommand::operator!=(const LoadCommand& rhs) const {
  return !(*this == rhs);
}

std::ostream& LoadCommand::print(std::ostream& os) const {
  os << std::hex;
  os << "Command : " << to_string(command()) << std::endl;
  os << "Offset  : " << command_offset() << std::endl;
  os << "Size    : " << size() << std::endl;
  return os;
}

std::ostream& operator<<(std::ostream& os, const LoadCommand& cmd) {
  return cmd.print(os);
}

}
}
