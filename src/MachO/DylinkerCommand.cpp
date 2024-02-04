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
#include <iomanip>
#include "LIEF/utils.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DylinkerCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

DylinkerCommand::DylinkerCommand() = default;
DylinkerCommand& DylinkerCommand::operator=(const DylinkerCommand&) = default;
DylinkerCommand::DylinkerCommand(const DylinkerCommand&) = default;
DylinkerCommand::~DylinkerCommand() = default;

DylinkerCommand::DylinkerCommand(const details::dylinker_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize}
{}

DylinkerCommand::DylinkerCommand(std::string name) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(LIEF::MachO::LOAD_COMMAND_TYPES::LC_LOAD_DYLINKER),
                           static_cast<uint32_t>(align(sizeof(details::dylinker_command) + name.size() + 1, sizeof(uint64_t)))},
  name_{name}
{
  this->data(LoadCommand::raw_t(size(), 0));
}

DylinkerCommand* DylinkerCommand::clone() const {
  return new DylinkerCommand(*this);
}

const std::string& DylinkerCommand::name() const {
  return name_;
}

void DylinkerCommand::name(const std::string& name) {
  name_ = name;
}


void DylinkerCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}




bool DylinkerCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_LOAD_DYLINKER ||
         type == LOAD_COMMAND_TYPES::LC_ID_DYLINKER;
}

std::ostream& DylinkerCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(35) << name();
  return os;
}

}
}
