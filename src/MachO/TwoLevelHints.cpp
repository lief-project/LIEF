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

#include "LIEF/MachO/TwoLevelHints.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

TwoLevelHints::TwoLevelHints() = default;
TwoLevelHints& TwoLevelHints::operator=(const TwoLevelHints&) = default;
TwoLevelHints::TwoLevelHints(const TwoLevelHints&) = default;
TwoLevelHints::~TwoLevelHints() = default;

TwoLevelHints::TwoLevelHints(const details::twolevel_hints_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  offset_{cmd.offset},
  original_nb_hints_{cmd.nhints}
{}

TwoLevelHints* TwoLevelHints::clone() const {
  return new TwoLevelHints(*this);
}

void TwoLevelHints::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool TwoLevelHints::operator==(const TwoLevelHints& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool TwoLevelHints::operator!=(const TwoLevelHints& rhs) const {
  return !(*this == rhs);
}

bool TwoLevelHints::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_TWOLEVEL_HINTS;
}


std::ostream& TwoLevelHints::print(std::ostream& os) const {
  LoadCommand::print(os);
  return os;
}


}
}
