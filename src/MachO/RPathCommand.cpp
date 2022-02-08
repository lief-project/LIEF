/* Copyright 2017 - 2021 J.Rieck (based on R. Thomas's work)
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

#include "LIEF/MachO/RPathCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

RPathCommand::RPathCommand() = default;
RPathCommand& RPathCommand::operator=(const RPathCommand&) = default;
RPathCommand::RPathCommand(const RPathCommand&) = default;
RPathCommand::~RPathCommand() = default;

RPathCommand::RPathCommand(const details::rpath_command& rpath) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(rpath.cmd), rpath.cmdsize}
{}

RPathCommand* RPathCommand::clone() const {
  return new RPathCommand(*this);
}

const std::string& RPathCommand::path() const {
  return path_;
}

void RPathCommand::path(const std::string& path) {
  path_ = path;
}


void RPathCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool RPathCommand::operator==(const RPathCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RPathCommand::operator!=(const RPathCommand& rhs) const {
  return !(*this == rhs);
}

bool RPathCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_RPATH;
}

std::ostream& RPathCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::left
     << std::setw(10) << "Path: " << path();
  return os;
}


}
}
