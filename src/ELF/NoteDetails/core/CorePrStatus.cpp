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
#include <sstream>

#include "logging.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "ELF/Structures.hpp"

#include "CorePrStatus.tcc"

namespace LIEF {
namespace ELF {

CorePrStatus::CorePrStatus(Note& note):
  NoteDetails::NoteDetails{note}
{}

CorePrStatus CorePrStatus::make(Note& note) {
  CorePrStatus pinfo(note);
  pinfo.parse();
  return pinfo;
}

CorePrStatus* CorePrStatus::clone() const {
  return new CorePrStatus(*this);
}

const CorePrStatus::reg_context_t& CorePrStatus::reg_context() const {
  return ctx_;
}


const CorePrStatus::siginfo_t& CorePrStatus::siginfo() const {
  return siginfo_;
}

uint16_t CorePrStatus::current_sig() const {
  return cursig_;
}

uint64_t CorePrStatus::sigpend() const {
  return sigpend_;
}

uint64_t CorePrStatus::sighold() const {
  return sighold_;
}

int32_t CorePrStatus::pid() const {
  return pid_;
}

int32_t CorePrStatus::ppid() const {
  return ppid_;
}

int32_t CorePrStatus::pgrp() const {
  return pgrp_;
}

int32_t CorePrStatus::sid() const {
  return sid_;
}

CorePrStatus::timeval_t CorePrStatus::utime() const {
  return utime_;
}

CorePrStatus::timeval_t CorePrStatus::stime() const {
  return stime_;
}

CorePrStatus::timeval_t CorePrStatus::cutime() const {
  return cutime_;
}

CorePrStatus::timeval_t CorePrStatus::cstime() const {
  return cstime_;
}


uint64_t CorePrStatus::get(CorePrStatus::REGISTERS reg, bool* error) const {
  if (!has(reg)) {
    if (error != nullptr) {
      *error = true;
    }
    return 0;
  }

  if (error != nullptr) {
    *error = false;
  }
  return ctx_.at(reg);
}

bool CorePrStatus::has(CorePrStatus::REGISTERS reg) const {
  return ctx_.find(reg) != std::end(ctx_);
}


uint64_t CorePrStatus::pc() const {
  const ARCH arch = binary()->header().machine_type();
  switch (arch) {
    case ARCH::EM_386:     return get(REGISTERS::X86_EIP);
    case ARCH::EM_X86_64:  return get(REGISTERS::X86_64_RIP);
    case ARCH::EM_ARM:     return get(REGISTERS::ARM_R15);
    case ARCH::EM_AARCH64: return get(REGISTERS::AARCH64_PC);
    default:
      {
        LIEF_WARN("{} not supported", to_string(arch));
        return 0;
      }
  }
}

uint64_t CorePrStatus::sp() const {
  const ARCH arch = binary()->header().machine_type();
  switch (arch) {
    case ARCH::EM_386:     return get(REGISTERS::X86_ESP);
    case ARCH::EM_X86_64:  return get(REGISTERS::X86_64_RSP);
    case ARCH::EM_ARM:     return get(REGISTERS::ARM_R13);
    case ARCH::EM_AARCH64: return get(REGISTERS::AARCH64_X31);
    default:
      {
        LIEF_WARN("{} not supported", to_string(arch));
        return 0;
      }
  }

}


void CorePrStatus::siginfo(const CorePrStatus::siginfo_t& siginfo) {
  siginfo_ = siginfo;
  build();
}

void CorePrStatus::current_sig(uint16_t current_sig) {
  cursig_ = current_sig;
  build();
}

void CorePrStatus::sigpend(uint64_t sigpend) {
  sigpend_ = sigpend;
  build();
}

void CorePrStatus::sighold(uint64_t sighold) {
  sighold_ = sighold;
  build();
}

void CorePrStatus::pid(int32_t pid) {
  pid_ = pid;
  build();
}

void CorePrStatus::ppid(int32_t ppid) {
  ppid_ = ppid;
  build();
}

void CorePrStatus::pgrp(int32_t pgrp) {
  pgrp_ = pgrp;
  build();
}

void CorePrStatus::sid(int32_t sid) {
  sid_ = sid;
  build();
}

void CorePrStatus::utime(CorePrStatus::timeval_t utime) {
  utime_ = utime;
  build();
}

void CorePrStatus::stime(CorePrStatus::timeval_t stime) {
  stime_ = stime;
  build();
}

void CorePrStatus::cutime(CorePrStatus::timeval_t cutime) {
  cutime_ = cutime;
  build();
}

void CorePrStatus::cstime(CorePrStatus::timeval_t cstime) {
  cstime_ = cstime;
  build();
}

void CorePrStatus::reg_context(const reg_context_t& ctx) {
  ctx_ = ctx;
  build();
}

bool CorePrStatus::set(REGISTERS reg, uint64_t value) {
  ctx_[reg] = value;
  build();
  return true;
}

void CorePrStatus::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CorePrStatus::operator==(const CorePrStatus& rhs) const {
  if (this == &rhs) {
    return true;
  }

  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CorePrStatus::operator!=(const CorePrStatus& rhs) const {
  return !(*this == rhs);
}

uint64_t& CorePrStatus::operator[](REGISTERS reg) {
  return ctx_[reg];
}

void CorePrStatus::dump(std::ostream& os) const {
  static constexpr size_t WIDTH = 16;
  os << std::left;

  os << std::setw(WIDTH) << std::setfill(' ') << "Siginfo: "<< std::dec;
    dump(os, siginfo());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Current Signal: "<< std::dec
     << current_sig() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Pending signal: "<< std::dec
     << sigpend() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Signal held: "<< std::dec
     << sighold() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "PID: "<< std::dec
     << pid() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "PPID: "<< std::dec
     << ppid() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "PGRP: "<< std::dec
     << pgrp() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "SID: "<< std::dec
     << sid() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "utime: "<< std::dec;
    dump(os, utime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "stime: "<< std::dec;
    dump(os, stime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "cutime: "<< std::dec;
    dump(os, cutime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "cstime: "<< std::dec;
    dump(os, cstime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Registers: "<< std::dec << std::endl;
    dump(os, reg_context());
  os << std::endl;

}

std::ostream& CorePrStatus::dump(std::ostream& os, const CorePrStatus::timeval_t& time) {
  os << std::dec;
  os << time.sec << ":" << time.usec;
  return os;
}

std::ostream& CorePrStatus::dump(std::ostream& os, const CorePrStatus::siginfo_t& siginfo) {
  os << std::dec;
  os << siginfo.si_signo << " - " << siginfo.si_code << " - " << siginfo.si_errno;
  return os;
}

std::ostream& CorePrStatus::dump(std::ostream& os, const reg_context_t& ctx) {

  for (const auto& reg_val : ctx) {
    os << std::setw(14) << std::setfill(' ') << to_string(reg_val.first) << ": " << std::hex << std::showbase << reg_val.second << std::endl;
  }
  return os;
}


void CorePrStatus::parse() {
  if (binary()->type() == ELF_CLASS::ELFCLASS64) {
    parse_<details::ELF64>();
  } else if (binary()->type() == ELF_CLASS::ELFCLASS32) {
    parse_<details::ELF32>();
  }
}

void CorePrStatus::build() {
  if (binary()->type() == ELF_CLASS::ELFCLASS64) {
    build_<details::ELF64>();
  } else if (binary()->type() == ELF_CLASS::ELFCLASS32) {
    build_<details::ELF32>();
  }
}


std::pair<size_t, size_t> CorePrStatus::reg_enum_range() const {
  const ARCH arch = binary()->header().machine_type();

  size_t enum_start = 0;
  size_t enum_end   = 0;

  switch (arch) {
    case ARCH::EM_386:
      {
        enum_start = static_cast<size_t>(REGISTERS::X86_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::X86_END);
        break;
      }

    case ARCH::EM_X86_64:
      {
        enum_start = static_cast<size_t>(REGISTERS::X86_64_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::X86_64_END);
        break;
      }

    case ARCH::EM_ARM:
      {
        enum_start = static_cast<size_t>(REGISTERS::ARM_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::ARM_END);
        break;
      }

    case ARCH::EM_AARCH64:
      {
        enum_start = static_cast<size_t>(REGISTERS::AARCH64_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::AARCH64_END);
        break;
      }

    default:
      {
        LIEF_WARN("{} not supported", to_string(arch));
      }
  }
  return {enum_start, enum_end};
}

std::ostream& operator<<(std::ostream& os, const CorePrStatus& note) {
  note.dump(os);
  return os;
}



CorePrStatus::~CorePrStatus() = default;

} // namespace ELF
} // namespace LIEF
