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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/MainCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

MainCommand& MainCommand::operator=(const MainCommand&) = default;
MainCommand::MainCommand(const MainCommand&) = default;
MainCommand::~MainCommand() = default;

MainCommand::MainCommand() = default;


MainCommand::MainCommand(const details::entry_point_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  entrypoint_{cmd.entryoff},
  stack_size_{cmd.stacksize}
{}

MainCommand* MainCommand::clone() const {
  return new MainCommand(*this);
}


uint64_t MainCommand::entrypoint() const {
  return entrypoint_;
}

uint64_t MainCommand::stack_size() const {
  return stack_size_;
}

void MainCommand::entrypoint(uint64_t entrypoint) {
  entrypoint_ = entrypoint;
}

void MainCommand::stack_size(uint64_t stacksize) {
  stack_size_ = stacksize;
}

void MainCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool MainCommand::operator==(const MainCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool MainCommand::operator!=(const MainCommand& rhs) const {
  return !(*this == rhs);
}


bool MainCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_MAIN;
}


std::ostream& MainCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << "Entrypoint: " << "0x" << entrypoint()
     << std::endl
     << "Stack size: " << "0x" << stack_size();
  return os;
}

}
}
