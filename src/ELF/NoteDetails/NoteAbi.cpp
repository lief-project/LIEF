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

NoteAbi* NoteAbi::clone() const {
  return new NoteAbi(*this);
}

NoteAbi::NoteAbi(Note& note) :
  NoteDetails::NoteDetails{note},
  version_{{0, 0, 0}},
  abi_{NOTE_ABIS::ELF_NOTE_UNKNOWN}
{}

NoteAbi::version_t NoteAbi::version() const {
  return version_;
}

NOTE_ABIS NoteAbi::abi() const {
  return abi_;
}

void NoteAbi::parse() {
  const description_t& desc = description();

  // Parse ABI
  if (desc.size() < (abi_offset + abi_size)) {
    return;
  }
  abi_ = static_cast<NOTE_ABIS>(*reinterpret_cast<const uint32_t*>(desc.data()));

  // Parse Version
  if (desc.size() < (version_offset + version_size)) {
    return;
  }

  const auto* version = reinterpret_cast<const uint32_t*>(desc.data() + version_offset);
  version_ = {{version[0], version[1], version[2]}};
}


void NoteAbi::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool NoteAbi::operator==(const NoteAbi& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool NoteAbi::operator!=(const NoteAbi& rhs) const {
  return !(*this == rhs);
}

void NoteAbi::dump(std::ostream& os) const {
    version_t version = this->version();
    std::string version_str;
    // Major
    version_str += std::to_string(std::get<0>(version));
    version_str += ".";

    // Minor
    version_str += std::to_string(std::get<1>(version));
    version_str += ".";

    // Patch
    version_str += std::to_string(std::get<2>(version));

    os << std::setw(33) << std::setfill(' ') << "ABI:"     << to_string(abi()) << std::endl;
    os << std::setw(33) << std::setfill(' ') << "Version:" << version_str           << std::endl;
}

std::ostream& operator<<(std::ostream& os, const NoteAbi& note) {
  note.dump(os);
  return os;
}

NoteAbi::~NoteAbi() = default;

} // namespace ELF
} // namespace LIEF
