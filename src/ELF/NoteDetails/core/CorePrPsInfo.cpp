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

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Note.hpp"

#include "ELF/Structures.hpp"

#include "CorePrPsInfo.tcc"

namespace LIEF {
namespace ELF {

CorePrPsInfo::CorePrPsInfo(Note& note):
  NoteDetails::NoteDetails{note},
  flags_(0),
  uid_(0),
  gid_(0),
  pid_(0),
  ppid_(0),
  pgrp_(0),
  sid_(0)
{}

CorePrPsInfo CorePrPsInfo::make(Note& note) {
  CorePrPsInfo pinfo(note);
  pinfo.parse();
  return pinfo;
}

CorePrPsInfo* CorePrPsInfo::clone() const {
  return new CorePrPsInfo(*this);
}

std::string CorePrPsInfo::file_name() const {
  return file_name_;
}

uint64_t CorePrPsInfo::flags() const {
  return flags_;
}

uint32_t CorePrPsInfo::uid() const {
  return uid_;
}

uint32_t CorePrPsInfo::gid() const {
  return gid_;
}

int32_t CorePrPsInfo::pid() const {
  return pid_;
}

int32_t CorePrPsInfo::ppid() const {
  return ppid_;
}

int32_t CorePrPsInfo::pgrp() const {
  return pgrp_;
}

int32_t CorePrPsInfo::sid() const {
  return sid_;
}

void CorePrPsInfo::file_name(const std::string& file_name) {
  file_name_ = file_name;
  build();
}

void CorePrPsInfo::flags(uint64_t flags) {
  flags_ = flags;
  build();
}

void CorePrPsInfo::uid(uint32_t uid) {
  uid_ = uid;
  build();
}

void CorePrPsInfo::gid(uint32_t gid) {
  gid_ = gid;
  build();
}

void CorePrPsInfo::pid(int32_t pid) {
  pid_ = pid;
  build();
}

void CorePrPsInfo::ppid(int32_t ppid) {
  ppid_ = ppid;
  build();
}

void CorePrPsInfo::pgrp(int32_t pgrp) {
  pgrp_ = pgrp;
  build();
}

void CorePrPsInfo::sid(int32_t sid) {
  sid_ = sid;
  build();
}

void CorePrPsInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CorePrPsInfo::operator==(const CorePrPsInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CorePrPsInfo::operator!=(const CorePrPsInfo& rhs) const {
  return !(*this == rhs);
}

void CorePrPsInfo::dump(std::ostream& os) const {
  os << std::left;
  os << std::setw(12) << std::setfill(' ') << "File name: " << std::dec << file_name() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "UID: " << std::dec << uid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "GID: " << std::dec << gid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "PID: " << std::dec << pid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "PPID: " << std::dec << ppid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "PGRP: " << std::dec << pgrp() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "SID: " << std::dec << sid() << std::endl;
}

void CorePrPsInfo::parse() {
  if (binary()->type() == ELF_CLASS::ELFCLASS64) {
    parse_<details::ELF64>();
  } else if (binary()->type() == ELF_CLASS::ELFCLASS32) {
    parse_<details::ELF32>();
  }
}

void CorePrPsInfo::build() {
  if (binary()->type() == ELF_CLASS::ELFCLASS64) {
    build_<details::ELF64>();
  } else if (binary()->type() == ELF_CLASS::ELFCLASS32) {
    build_<details::ELF32>();
  }
}

std::ostream& operator<<(std::ostream& os, const CorePrPsInfo& note) {
  note.dump(os);
  return os;
}

CorePrPsInfo::~CorePrPsInfo() = default;

} // namespace ELF
} // namespace LIEF
