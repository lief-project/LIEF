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
#include <iostream>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

LoadCommand::LoadCommand(void) = default;
LoadCommand& LoadCommand::operator=(const LoadCommand&) = default;
LoadCommand::LoadCommand(const LoadCommand&) = default;
LoadCommand::~LoadCommand(void) = default;

LoadCommand::LoadCommand(LOAD_COMMAND_TYPES type, uint32_t size) :
  originalData_{},
  command_{type},
  size_{size},
  commandOffset_{0}
{}

LoadCommand::LoadCommand(const load_command* command) :
  command_{static_cast<LOAD_COMMAND_TYPES>(command->cmd)},
  size_{command->cmdsize},
  commandOffset_{0}
{}


void LoadCommand::swap(LoadCommand& other) {
  std::swap(this->originalData_,  other.originalData_);
  std::swap(this->command_,       other.command_);
  std::swap(this->size_,          other.size_);
  std::swap(this->commandOffset_, other.commandOffset_);
}

LOAD_COMMAND_TYPES LoadCommand::command(void) const {
  return this->command_;
}

uint32_t LoadCommand::size(void) const {
  return this->size_;
}

const std::vector<uint8_t>& LoadCommand::data(void) const {
  return this->originalData_;
}


uint64_t LoadCommand::command_offset(void) const {
  return this->commandOffset_;
}

void LoadCommand::data(const std::vector<uint8_t>& data) {
  this->originalData_ = std::move(data);
}

void LoadCommand::command(LOAD_COMMAND_TYPES command) {
  this->command_ = command;
}

void LoadCommand::size(uint32_t size) {
  this->size_ = size;
}


void LoadCommand::command_offset(uint64_t offset) {
  this->commandOffset_ = offset;
}


void LoadCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool LoadCommand::operator==(const LoadCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LoadCommand::operator!=(const LoadCommand& rhs) const {
  return not (*this == rhs);
}

std::ostream& LoadCommand::print(std::ostream& os) const {
  os << std::hex;
  os << "Command : " << to_string(this->command()) << std::endl;
  os << "Offset  : " << this->command_offset() << std::endl;
  os << "Size    : " << this->size() << std::endl;
  return os;
}

std::ostream& operator<<(std::ostream& os, const LoadCommand& cmd) {
  return cmd.print(os);
}

}
}
