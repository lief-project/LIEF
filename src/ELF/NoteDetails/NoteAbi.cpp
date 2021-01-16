/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"

namespace LIEF {
namespace ELF {

NoteAbi NoteAbi::make(Note& note) {
  NoteAbi abi = note;
  abi.parse();
  return abi;
}

NoteAbi* NoteAbi::clone(void) const {
  return new NoteAbi(*this);
}

NoteAbi::NoteAbi(Note& note) :
  NoteDetails::NoteDetails{note},
  version_{{0, 0, 0}},
  abi_{NOTE_ABIS::ELF_NOTE_UNKNOWN}
{}

NoteAbi::version_t NoteAbi::version(void) const {
  return this->version_;
}

NOTE_ABIS NoteAbi::abi(void) const {
  return this->abi_;
}

void NoteAbi::parse(void) {
  const description_t& description = this->description();

  // Parse ABI
  if (description.size() < (abi_offset + abi_size)) {
    return;
  }
  this->abi_ = static_cast<NOTE_ABIS>(*reinterpret_cast<const uint32_t*>(description.data()));

  // Parse Version
  if (description.size() < (version_offset + version_size)) {
    return;
  }

  const uint32_t* version = reinterpret_cast<const uint32_t*>(description.data() + version_offset);
  this->version_ = {{version[0], version[1], version[2]}};
}


void NoteAbi::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool NoteAbi::operator==(const NoteAbi& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool NoteAbi::operator!=(const NoteAbi& rhs) const {
  return not (*this == rhs);
}

void NoteAbi::dump(std::ostream& os) const {
    version_t version = this->version();
    std::string version_str = "";
    // Major
    version_str += std::to_string(std::get<0>(version));
    version_str += ".";

    // Minor
    version_str += std::to_string(std::get<1>(version));
    version_str += ".";

    // Patch
    version_str += std::to_string(std::get<2>(version));

    os << std::setw(33) << std::setfill(' ') << "ABI:"     << to_string(this->abi()) << std::endl;
    os << std::setw(33) << std::setfill(' ') << "Version:" << version_str           << std::endl;
}

std::ostream& operator<<(std::ostream& os, const NoteAbi& note) {
  note.dump(os);
  return os;
}

NoteAbi::~NoteAbi(void) = default;

} // namespace ELF
} // namespace LIEF
