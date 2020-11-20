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

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Note.hpp"

#include "CorePrPsInfo.tcc"

namespace LIEF {
namespace ELF {

CorePrPsInfo::CorePrPsInfo(Note& note):
  NoteDetails::NoteDetails{note},
  file_name_(""),
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

CorePrPsInfo* CorePrPsInfo::clone(void) const {
  return new CorePrPsInfo(*this);
}

std::string CorePrPsInfo::file_name(void) const {
  return this->file_name_;
}

uint64_t CorePrPsInfo::flags(void) const {
  return this->flags_;
}

uint32_t CorePrPsInfo::uid(void) const {
  return this->uid_;
}

uint32_t CorePrPsInfo::gid(void) const {
  return this->gid_;
}

int32_t CorePrPsInfo::pid(void) const {
  return this->pid_;
}

int32_t CorePrPsInfo::ppid(void) const {
  return this->ppid_;
}

int32_t CorePrPsInfo::pgrp(void) const {
  return this->pgrp_;
}

int32_t CorePrPsInfo::sid(void) const {
  return this->sid_;
}

void CorePrPsInfo::file_name(const std::string& file_name) {
  this->file_name_ = file_name;
  this->build();
}

void CorePrPsInfo::flags(uint64_t flags) {
  this->flags_ = flags;
  this->build();
}

void CorePrPsInfo::uid(uint32_t uid) {
  this->uid_ = uid;
  this->build();
}

void CorePrPsInfo::gid(uint32_t gid) {
  this->gid_ = gid;
  this->build();
}

void CorePrPsInfo::pid(int32_t pid) {
  this->pid_ = pid;
  this->build();
}

void CorePrPsInfo::ppid(int32_t ppid) {
  this->ppid_ = ppid;
  this->build();
}

void CorePrPsInfo::pgrp(int32_t pgrp) {
  this->pgrp_ = pgrp;
  this->build();
}

void CorePrPsInfo::sid(int32_t sid) {
  this->sid_ = sid;
  this->build();
}

void CorePrPsInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CorePrPsInfo::operator==(const CorePrPsInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CorePrPsInfo::operator!=(const CorePrPsInfo& rhs) const {
  return not (*this == rhs);
}

void CorePrPsInfo::dump(std::ostream& os) const {
  os << std::left;
  os << std::setw(12) << std::setfill(' ') << "File name: " << std::dec << this->file_name() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "UID: " << std::dec << this->uid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "GID: " << std::dec << this->gid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "PID: " << std::dec << this->pid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "PPID: " << std::dec << this->ppid() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "PGRP: " << std::dec << this->pgrp() << std::endl;
  os << std::setw(12) << std::setfill(' ') << "SID: " << std::dec << this->sid() << std::endl;
}

void CorePrPsInfo::parse(void) {
  if (this->binary()->type() == ELF_CLASS::ELFCLASS64) {
    this->parse_<ELF64>();
  } else if (this->binary()->type() == ELF_CLASS::ELFCLASS32) {
    this->parse_<ELF32>();
  }
}

void CorePrPsInfo::build(void) {
  if (this->binary()->type() == ELF_CLASS::ELFCLASS64) {
    this->build_<ELF64>();
  } else if (this->binary()->type() == ELF_CLASS::ELFCLASS32) {
    this->build_<ELF32>();
  }
}

std::ostream& operator<<(std::ostream& os, const CorePrPsInfo& note) {
  note.dump(os);
  return os;
}

CorePrPsInfo::~CorePrPsInfo(void) = default;

} // namespace ELF
} // namespace LIEF
