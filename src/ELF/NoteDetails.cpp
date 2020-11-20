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
#include <numeric>
#include <sstream>
#include <algorithm>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "logging.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/NoteDetails.hpp"
#include "LIEF/ELF/Note.hpp"

namespace LIEF {
namespace ELF {

NoteDetails::~NoteDetails(void) = default;


NoteDetails::NoteDetails():
  note_{nullptr}
{}

NoteDetails::NoteDetails(Note& note):
  note_{&note}
{}

NoteDetails* NoteDetails::clone(void) const {
  return new NoteDetails(*this);
}

const Note::description_t& NoteDetails::description(void) const {
  if (this->note_ == nullptr) {
    return this->empty_;
  }
  return this->note_->description();
}

Note::description_t& NoteDetails::description(void) {
  if (this->note_ == nullptr) {
    return this->empty_;
  }
  return this->note_->description();
}


Binary* NoteDetails::binary(void) {
  return const_cast<Binary*>(static_cast<const NoteDetails*>(this)->binary());
}


const Binary* NoteDetails::binary(void) const {
  if (this->note_ == nullptr) {
    return nullptr;
  }
  return this->note_->binary_;
}

void NoteDetails::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool NoteDetails::operator==(const NoteDetails& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool NoteDetails::operator!=(const NoteDetails& rhs) const {
  return not (*this == rhs);
}


void NoteDetails::dump(std::ostream&) const {
}

void NoteDetails::parse(void) {
}

void NoteDetails::build(void) {
}


std::ostream& operator<<(std::ostream& os, const NoteDetails& note) {
  note.dump(os);
  return os;

}

} // namespace ELF
} // namespace LIEF
