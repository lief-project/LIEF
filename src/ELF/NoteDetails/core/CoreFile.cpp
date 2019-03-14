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

#include "CoreFile.tcc"

namespace LIEF {
namespace ELF {

CoreFile::CoreFile(Note& note):
  NoteDetails::NoteDetails{note},
  files_({})
{}

CoreFile CoreFile::make(Note& note) {
  CoreFile file(note);
  file.parse();
  return file;
}


uint64_t CoreFile::count(void) const {
  return this->files_.size();
}

std::vector<CoreFileEntry> CoreFile::files(void) const {
  std::vector<CoreFileEntry> entries;
  entries.reserve(this->count());
  std::copy(
      std::begin(this->files_),
      std::end(this->files_),
      std::back_inserter(entries));
  return entries;
}


void CoreFile::files(const std::vector<CoreFileEntry>& files) {
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

void CoreFile::dump(std::ostream&) const {
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

} // namespace ELF
} // namespace LIEF
