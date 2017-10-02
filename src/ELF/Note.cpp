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

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/Note.hpp"

namespace LIEF {
namespace ELF {
Note& Note::operator=(const Note&) = default;
Note::Note(const Note&)            = default;
Note::~Note(void)                  = default;

Note::Note(void) :
  name_{""},
  type_{0},
  description_{}
{}

Note::Note(const std::string& name, uint32_t type, const std::vector<uint8_t>& description):
  name_{name},
  type_{type},
  description_{description}
{}


Note::Note(const std::string& name, NOTE_TYPES type, const std::vector<uint8_t>& description):
  Note::Note{name, static_cast<uint32_t>(type), description}
{}

const std::string& Note::name(void) const {
  return this->name_;
}

uint32_t Note::type(void) const {
  return this->type_;
}

const std::vector<uint8_t>& Note::description(void) const {
  return this->description_;
}


NOTE_ABIS Note::abi(void) const {
  if (static_cast<NOTE_TYPES>(this->type()) != NOTE_TYPES::NT_GNU_ABI_TAG) {
    throw type_error(std::string("This note is not a ") + to_string(NOTE_TYPES::NT_GNU_ABI_TAG) + " one!");
  }

  const std::vector<uint8_t>& description = this->description();
  if (description.size() < sizeof(uint32_t)) {
    throw corrupted("The description of the note seems corrupted");
  }

  return static_cast<NOTE_ABIS>(*reinterpret_cast<const uint32_t*>(description.data()));
}

std::tuple<uint32_t, uint32_t, uint32_t> Note::version(void) const {
  if (static_cast<NOTE_TYPES>(this->type()) != NOTE_TYPES::NT_GNU_ABI_TAG) {
    throw type_error(std::string("This note is not a ") + to_string(NOTE_TYPES::NT_GNU_ABI_TAG) + " one!");
  }

  const std::vector<uint8_t>& description = this->description();
  if (description.size() < (sizeof(uint32_t) + 3 * sizeof(uint32_t))) {
    throw corrupted("The description of the note seems corrupted");
  }

  const uint32_t* version = reinterpret_cast<const uint32_t*>(description.data());
  return std::tuple<uint32_t, uint32_t, uint32_t>{version[1], version[2], version[3]};
}


void Note::name(const std::string& name) {
  this->name_ = name;
}
void Note::type(uint32_t type) {
  this->type_ = type;
}

void Note::description(const std::vector<uint8_t>& description) {
  this->description_ = description;
}


uint64_t Note::size(void) const {
  uint64_t size = 0;
  size += 3 * sizeof(uint32_t);
  size += this->name().size() + 1;
  size = align(size, sizeof(uint32_t));
  size += this->description().size();
  size = align(size, sizeof(uint32_t));
  return size;
}

void Note::accept(Visitor& visitor) const {
  visitor.visit(this->name());
  visitor.visit(this->type());
  visitor.visit(this->description());
}


bool Note::operator==(const Note& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Note::operator!=(const Note& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Note& note) {

  const std::vector<uint8_t>& description = note.description();

  std::string description_str = std::accumulate(
      std::begin(description),
      std::begin(description) + std::min<size_t>(16, description.size()), std::string{},
      [] (const std::string& a, uint8_t v) {
        std::ostringstream hex_v;
        hex_v << std::setw(2) << std::setfill('0') << std::hex;
        hex_v << static_cast<uint32_t>(v);

        return a.empty() ? "[" + hex_v.str() : a + " " + hex_v.str();
      });
  if (description.size() > 16) {
    description_str += " ...";
  }
  description_str += "]";
  os << std::hex << std::left;
  os << std::setw(33) << std::setfill(' ') << "Name:" << note.name() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Type:" << to_string(static_cast<NOTE_TYPES>(note.type())) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Description:" << description_str << std::endl;


  // ABI TAG
  if (static_cast<NOTE_TYPES>(note.type()) == NOTE_TYPES::NT_GNU_ABI_TAG) {
    try {
      std::tuple<uint32_t, uint32_t, uint32_t> version = note.version();
      std::string version_str = "";
      // Major
      version_str += std::to_string(std::get<0>(version));
      version_str += ".";

      // Minor
      version_str += std::to_string(std::get<1>(version));
      version_str += ".";

      // Patch
      version_str += std::to_string(std::get<2>(version));

      os << std::setw(33) << std::setfill(' ') << "ABI:"     << to_string(note.abi()) << std::endl;
      os << std::setw(33) << std::setfill(' ') << "Version:" << version_str           << std::endl;
    } catch (const corrupted&) {
    }
  }


  // GOLD VERSION
  if (static_cast<NOTE_TYPES>(note.type()) == NOTE_TYPES::NT_GNU_GOLD_VERSION) {
    std::string version_str{reinterpret_cast<const char*>(description.data()), description.size()};
    os << std::setw(33) << std::setfill(' ') << "Version:" << version_str << std::endl;
  }


  // BUILD ID
  if (static_cast<NOTE_TYPES>(note.type()) == NOTE_TYPES::NT_GNU_BUILD_ID) {
    std::string hash = std::accumulate(
      std::begin(description),
      std::end(description), std::string{},
      [] (const std::string& a, uint8_t v) {
        std::ostringstream hex_v;
        hex_v << std::setw(2) << std::setfill('0') << std::hex;
        hex_v << static_cast<uint32_t>(v);

        return a + hex_v.str();
      });

    os << std::setw(33) << std::setfill(' ') << "ID Hash:" << hash << std::endl;
  }
  return os;

}

} // namespace ELF
} // namespace LIEF
