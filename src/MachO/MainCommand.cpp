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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/MainCommand.hpp"

namespace LIEF {
namespace MachO {

MainCommand& MainCommand::operator=(const MainCommand&) = default;
MainCommand::MainCommand(const MainCommand&) = default;
MainCommand::~MainCommand(void) = default;

MainCommand::MainCommand(void) :
  LoadCommand::LoadCommand{},
  entrypoint_{0},
  stackSize_{0}
{}

MainCommand::MainCommand(const entry_point_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  entrypoint_{cmd->entryoff},
  stackSize_{cmd->stacksize}
{}


uint64_t MainCommand::entrypoint(void) const {
  return this->entrypoint_;
}

uint64_t MainCommand::stack_size(void) const {
  return this->stackSize_;
}

void MainCommand::entrypoint(uint64_t entrypoint) {
  this->entrypoint_ = entrypoint;
}

void MainCommand::stack_size(uint64_t stacksize) {
  this->stackSize_ = stacksize;
}

void MainCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool MainCommand::operator==(const MainCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool MainCommand::operator!=(const MainCommand& rhs) const {
  return not (*this == rhs);
}

std::ostream& MainCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << "Entrypoint: " << "0x" << this->entrypoint()
     << std::endl
     << "Stack size: " << "0x" << this->stack_size();
  return os;
}

}
}
