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
#include "LIEF/ELF/Binary.hpp"

#include "CoreFile.tcc"

namespace LIEF {
namespace ELF {

CoreFile::CoreFile(Note& note):
  NoteDetails::NoteDetails{note},
  files_{}
{}

CoreFile CoreFile::make(Note& note) {
  CoreFile file(note);
  file.parse();
  return file;
}

CoreFile* CoreFile::clone(void) const {
  return new CoreFile(*this);
}


uint64_t CoreFile::count(void) const {
  return this->files_.size();
}

const CoreFile::files_t& CoreFile::files(void) const {
  return this->files_;
}


CoreFile::iterator CoreFile::begin(void) {
  return std::begin(this->files_);
}

CoreFile::iterator CoreFile::end(void) {
  return std::end(this->files_);
}

CoreFile::const_iterator CoreFile::begin(void) const {
  return std::begin(this->files_);
}

CoreFile::const_iterator CoreFile::end(void) const {
  return std::end(this->files_);
}

void CoreFile::files(const CoreFile::files_t& files) {
  this->files_ = files;
  this->build();
}


void CoreFile::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CoreFile::operator==(const CoreFile& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CoreFile::operator!=(const CoreFile& rhs) const {
  return not (*this == rhs);
}

void CoreFile::dump(std::ostream& os) const {
  static constexpr size_t WIDTH = 16;
  os << std::left;

  os << std::setw(WIDTH) << std::setfill(' ') << "Files: "<< std::dec << std::endl;
  for (const CoreFileEntry& file : this->files()) {
    os << " - ";
    os << file.path << " ";
    os << "[" << std::hex << std::showbase << file.start << ", " << file.end << "] ";
    os << file.file_ofs;
    os << std::endl;
  }
  os << std::endl;
}

void CoreFile::parse(void) {
  if (this->binary()->type() == ELF_CLASS::ELFCLASS64) {
    this->parse_<ELF64>();
  } else if (this->binary()->type() == ELF_CLASS::ELFCLASS32) {
    this->parse_<ELF32>();
  }
}

void CoreFile::build(void) {
  if (this->binary()->type() == ELF_CLASS::ELFCLASS64) {
    this->build_<ELF64>();
  } else if (this->binary()->type() == ELF_CLASS::ELFCLASS32) {
    this->build_<ELF32>();
  }
}

std::ostream& operator<<(std::ostream& os, const CoreFile& note) {
  note.dump(os);
  return os;
}

CoreFile::~CoreFile(void) = default;


std::ostream& operator<<(std::ostream& os, const CoreFileEntry& entry) {
  os << std::hex << std::showbase;
  os << entry.path << ": [" << entry.start << ", " << entry.end << "]@" << entry.file_ofs;
  return os;
}

} // namespace ELF
} // namespace LIEF
