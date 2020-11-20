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
#include <sstream>

#include "logging.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"

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

CoreSigInfo* CoreSigInfo::clone(void) const {
  return new CoreSigInfo(*this);
}

int32_t CoreSigInfo::signo(void) const {
  return this->siginfo_.si_signo;
}

int32_t CoreSigInfo::sigcode(void) const {
  return this->siginfo_.si_code;
}

int32_t CoreSigInfo::sigerrno(void) const {
  return this->siginfo_.si_errno;
}

void CoreSigInfo::signo(int32_t signo) {
  this->siginfo_.si_signo = signo;
  this->build();
}

void CoreSigInfo::sigcode(int32_t sigcode) {
  this->siginfo_.si_code = sigcode;
  this->build();
}

void CoreSigInfo::sigerrno(int32_t sigerrno) {
  this->siginfo_.si_errno = sigerrno;
  this->build();
}

void CoreSigInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CoreSigInfo::operator==(const CoreSigInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CoreSigInfo::operator!=(const CoreSigInfo& rhs) const {
  return not (*this == rhs);
}

void CoreSigInfo::dump(std::ostream& os) const {
  static constexpr size_t WIDTH = 16;
  os << std::left;

  os << std::setw(WIDTH) << std::setfill(' ') << "Signo: "<< std::dec
     << this->signo() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Code: "<< std::dec
     << this->sigcode() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Errno: "<< std::dec
     << this->sigerrno() << std::endl;
}


void CoreSigInfo::parse(void) {
  const Note::description_t& description = this->description();
  if (description.size() < sizeof(Elf_siginfo)) {
    return;
  }
  auto&& siginfo = reinterpret_cast<const Elf_siginfo*>(description.data());
  this->siginfo_ = *siginfo;
}


void CoreSigInfo::build(void) {
  Note::description_t& description = this->description();
  if (description.size() < sizeof(Elf_siginfo)) {
    description.resize(sizeof(Elf_siginfo));
  }
  std::copy(
    reinterpret_cast<const uint8_t*>(&this->siginfo_),
    reinterpret_cast<const uint8_t*>(&this->siginfo_) + sizeof(Elf_siginfo),
    std::begin(description));
}


std::ostream& operator<<(std::ostream& os, const CoreSigInfo& note) {
  note.dump(os);
  return os;
}


CoreSigInfo::~CoreSigInfo(void) = default;

} // namespace ELF
} // namespace LIEF
