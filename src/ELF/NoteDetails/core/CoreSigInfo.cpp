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

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"
#include "ELF/Structures.hpp"

namespace LIEF {
namespace ELF {

CoreSigInfo::CoreSigInfo(Note& note):
  NoteDetails::NoteDetails{note}
{}

CoreSigInfo CoreSigInfo::make(Note& note) {
  CoreSigInfo pinfo(note);
  pinfo.parse();
  return pinfo;
}

CoreSigInfo* CoreSigInfo::clone() const {
  return new CoreSigInfo(*this);
}

int32_t CoreSigInfo::signo() const {
  return siginfo_.si_signo;
}

int32_t CoreSigInfo::sigcode() const {
  return siginfo_.si_code;
}

int32_t CoreSigInfo::sigerrno() const {
  return siginfo_.si_errno;
}

void CoreSigInfo::signo(int32_t signo) {
  siginfo_.si_signo = signo;
  build();
}

void CoreSigInfo::sigcode(int32_t sigcode) {
  siginfo_.si_code = sigcode;
  build();
}

void CoreSigInfo::sigerrno(int32_t sigerrno) {
  siginfo_.si_errno = sigerrno;
  build();
}

void CoreSigInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CoreSigInfo::operator==(const CoreSigInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CoreSigInfo::operator!=(const CoreSigInfo& rhs) const {
  return !(*this == rhs);
}

void CoreSigInfo::dump(std::ostream& os) const {
  static constexpr size_t WIDTH = 16;
  os << std::left;

  os << std::setw(WIDTH) << std::setfill(' ') << "Signo: "<< std::dec
     << signo() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Code: "<< std::dec
     << sigcode() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Errno: "<< std::dec
     << sigerrno() << std::endl;
}


void CoreSigInfo::parse() {
  const Note::description_t& desc = description();
  if (desc.size() < sizeof(details::Elf_siginfo)) {
    return;
  }
  const auto* siginfo = reinterpret_cast<const details::Elf_siginfo*>(desc.data());
  siginfo_.si_signo = siginfo->si_signo;
  siginfo_.si_code  = siginfo->si_code;
  siginfo_.si_errno = siginfo->si_errno;
}


void CoreSigInfo::build() {
  Note::description_t& desc = description();
  if (desc.size() < sizeof(details::Elf_siginfo)) {
    desc.resize(sizeof(details::Elf_siginfo));
  }
  std::copy(
    reinterpret_cast<const uint8_t*>(&siginfo_),
    reinterpret_cast<const uint8_t*>(&siginfo_) + sizeof(details::Elf_siginfo),
    std::begin(desc));
}


std::ostream& operator<<(std::ostream& os, const CoreSigInfo& note) {
  note.dump(os);
  return os;
}


CoreSigInfo::~CoreSigInfo() = default;

} // namespace ELF
} // namespace LIEF
