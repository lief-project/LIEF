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
#include <numeric>
#include <iomanip>

#include "logging.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/ThreadCommand.hpp"

namespace LIEF {
namespace MachO {

ThreadCommand::ThreadCommand(void) = default;
ThreadCommand& ThreadCommand::operator=(const ThreadCommand&) = default;
ThreadCommand::ThreadCommand(const ThreadCommand&) = default;
ThreadCommand::~ThreadCommand(void) = default;

ThreadCommand::ThreadCommand(const thread_command *cmd, CPU_TYPES arch) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  flavor_{cmd->flavor},
  count_{cmd->count},
  architecture_{arch},
  state_{}
{}

ThreadCommand::ThreadCommand(uint32_t flavor, uint32_t count, CPU_TYPES arch) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(LIEF::MachO::LOAD_COMMAND_TYPES::LC_UNIXTHREAD),
                           static_cast<uint32_t>(sizeof(LIEF::MachO::thread_command) + count * sizeof(uint32_t))},
  flavor_{flavor},
  count_{count},
  architecture_{arch},
  state_(this->size() - sizeof(LIEF::MachO::thread_command), 0)
{
}

ThreadCommand* ThreadCommand::clone(void) const {
  return new ThreadCommand(*this);
}


uint32_t ThreadCommand::flavor(void) const {
  return this->flavor_;
}

uint32_t ThreadCommand::count(void) const {
  return this->count_;
}

CPU_TYPES ThreadCommand::architecture(void) const {
  return this->architecture_;
}

const std::vector<uint8_t>& ThreadCommand::state(void) const {
  return this->state_;
}

std::vector<uint8_t>& ThreadCommand::state(void) {
  return const_cast<std::vector<uint8_t>&>(static_cast<const ThreadCommand*>(this)->state());
}

uint64_t ThreadCommand::pc(void) const {
  uint64_t entry = 0;
  switch(this->architecture_) {
    case CPU_TYPES::CPU_TYPE_X86:
      {
        entry = reinterpret_cast<const x86_thread_state_t*>(this->state_.data())->eip;
        break;
      }

    case CPU_TYPES::CPU_TYPE_X86_64:
      {
        entry = reinterpret_cast<const x86_thread_state64_t*>(this->state_.data())->rip;
        break;
      }

    case CPU_TYPES::CPU_TYPE_ARM:
      {
        entry = reinterpret_cast<const arm_thread_state_t*>(this->state_.data())->r15;
        break;
      }

    case CPU_TYPES::CPU_TYPE_ARM64:
      {
        entry = reinterpret_cast<const arm_thread_state64_t*>(this->state_.data())->pc;
        break;
      }
    default:
      {
        LIEF_ERR("Unknown architecture");
      }
  }
  return entry;
}

void ThreadCommand::state(const std::vector<uint8_t>& state) {
  this->state_ = state;
}

void ThreadCommand::flavor(uint32_t flavor) {
  this->flavor_ = flavor;
}

void ThreadCommand::count(uint32_t count) {
  this->count_ = count;
}

void ThreadCommand::architecture(CPU_TYPES arch) {
  this->architecture_ = arch;
}

void ThreadCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ThreadCommand::operator==(const ThreadCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ThreadCommand::operator!=(const ThreadCommand& rhs) const {
  return not (*this == rhs);
}


std::ostream& ThreadCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(10) << "Flavor: " << "0x" << this->flavor()
     << std::endl
     << std::setw(10) << "Count: " << "0x" << this->count()
     << std::endl
     << std::setw(10) << "PC: " << "0x" << this->pc();
  return os;
}


}
}
