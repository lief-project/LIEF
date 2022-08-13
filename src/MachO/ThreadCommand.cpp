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

#include "logging.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/ThreadCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

ThreadCommand::ThreadCommand() = default;
ThreadCommand& ThreadCommand::operator=(const ThreadCommand&) = default;
ThreadCommand::ThreadCommand(const ThreadCommand&) = default;
ThreadCommand::~ThreadCommand() = default;

ThreadCommand::ThreadCommand(const details::thread_command& cmd, CPU_TYPES arch) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  flavor_{cmd.flavor},
  count_{cmd.count},
  architecture_{arch}
{}

ThreadCommand::ThreadCommand(uint32_t flavor, uint32_t count, CPU_TYPES arch) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(LIEF::MachO::LOAD_COMMAND_TYPES::LC_UNIXTHREAD),
                           static_cast<uint32_t>(sizeof(details::thread_command) + count * sizeof(uint32_t))},
  flavor_{flavor},
  count_{count},
  architecture_{arch},
  state_(size() - sizeof(details::thread_command), 0)
{
}

ThreadCommand* ThreadCommand::clone() const {
  return new ThreadCommand(*this);
}


uint32_t ThreadCommand::flavor() const {
  return flavor_;
}

uint32_t ThreadCommand::count() const {
  return count_;
}

CPU_TYPES ThreadCommand::architecture() const {
  return architecture_;
}

const std::vector<uint8_t>& ThreadCommand::state() const {
  return state_;
}

std::vector<uint8_t>& ThreadCommand::state() {
  return const_cast<std::vector<uint8_t>&>(static_cast<const ThreadCommand*>(this)->state());
}

uint64_t ThreadCommand::pc() const {
  uint64_t entry = 0;
  switch(architecture_) {
    case CPU_TYPES::CPU_TYPE_X86:
      {
        if (state_.size() < sizeof(details::x86_thread_state_t)) {
          return entry;
        }
        entry = reinterpret_cast<const details::x86_thread_state_t*>(state_.data())->eip;
        break;
      }

    case CPU_TYPES::CPU_TYPE_X86_64:
      {
        if (state_.size() < sizeof(details::x86_thread_state64_t)) {
          return entry;
        }
        entry = reinterpret_cast<const details::x86_thread_state64_t*>(state_.data())->rip;
        break;
      }

    case CPU_TYPES::CPU_TYPE_ARM:
      {
        if (state_.size() < sizeof(details::arm_thread_state_t)) {
          return entry;
        }
        entry = reinterpret_cast<const details::arm_thread_state_t*>(state_.data())->r15;
        break;
      }

    case CPU_TYPES::CPU_TYPE_ARM64:
      {
        if (state_.size() < sizeof(details::arm_thread_state64_t)) {
          return entry;
        }
        entry = reinterpret_cast<const details::arm_thread_state64_t*>(state_.data())->pc;
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
  state_ = state;
}

void ThreadCommand::flavor(uint32_t flavor) {
  flavor_ = flavor;
}

void ThreadCommand::count(uint32_t count) {
  count_ = count;
}

void ThreadCommand::architecture(CPU_TYPES arch) {
  architecture_ = arch;
}

void ThreadCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ThreadCommand::operator==(const ThreadCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ThreadCommand::operator!=(const ThreadCommand& rhs) const {
  return !(*this == rhs);
}

bool ThreadCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_THREAD ||
         type == LOAD_COMMAND_TYPES::LC_UNIXTHREAD;
}


std::ostream& ThreadCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(10) << "Flavor: " << "0x" << flavor()
     << std::endl
     << std::setw(10) << "Count: " << "0x" << count()
     << std::endl
     << std::setw(10) << "PC: " << "0x" << pc();
  return os;
}


}
}
