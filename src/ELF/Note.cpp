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

#include "LIEF/logging++.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails.hpp"
#include "LIEF/ELF/AndroidNote.hpp"

namespace LIEF {
namespace ELF {
constexpr Note::version_t Note::UNKNOWN_VERSION;

Note::~Note(void) = default;

Note& Note::operator=(Note other) {
  this->swap(other);
  return *this;
}

Note::Note(const Note& other):
  binary_(other.binary_),
  name_(other.name_),
  type_(other.type_),
  description_(other.description_)
{}

void Note::swap(Note& other) {
  std::swap(this->binary_,      other.binary_);
  std::swap(this->name_,        other.name_);
  std::swap(this->type_,        other.type_);
  std::swap(this->description_, other.description_);
  std::swap(this->details_,     other.details_);
}

Note::Note() :
  binary_{nullptr},
  name_{""},
  type_{NOTE_TYPES::NT_UNKNOWN},
  description_{},
  details_{std::make_pair(NOTE_TYPES::NT_UNKNOWN, std::unique_ptr<NoteDetails>(new NoteDetails()))}
{}

Note::Note(const std::string& name, uint32_t type, const description_t& description, Binary* binary):
  binary_{binary},
  name_{name},
  type_{static_cast<NOTE_TYPES>(type)},
  description_{description},
  details_{std::make_pair(NOTE_TYPES::NT_UNKNOWN, std::unique_ptr<NoteDetails>(new NoteDetails()))}
{}

Note::Note(const std::string& name, NOTE_TYPES type, const description_t& description, Binary* binary):
  Note::Note{name, static_cast<uint32_t>(type), description, binary}
{}

Note::Note(const std::string& name, NOTE_TYPES_CORE type, const description_t& description, Binary* binary):
  Note::Note{name, static_cast<uint32_t>(type), description, binary}
{
  this->is_core_ = true;
  this->details();
}


const std::string& Note::name(void) const {
  return this->name_;
}

NOTE_TYPES Note::type(void) const {
  return this->type_;
}

NOTE_TYPES_CORE Note::type_core(void) const {
  return static_cast<NOTE_TYPES_CORE>(this->type_);
}

const Note::description_t& Note::description(void) const {
  return this->description_;
}

Note::description_t& Note::description(void) {
  return this->description_;
}


NOTE_ABIS Note::abi(void) const {
  if (this->type() != NOTE_TYPES::NT_GNU_ABI_TAG) {
    return NOTE_ABIS::ELF_NOTE_UNKNOWN;
  }

  const description_t& description = this->description();
  if (description.size() < sizeof(uint32_t)) {
    LOG(WARNING) << "The description of the note seems corrupted";
    return NOTE_ABIS::ELF_NOTE_UNKNOWN;
  }

  return static_cast<NOTE_ABIS>(*reinterpret_cast<const uint32_t*>(description.data()));
}

Note::version_t Note::version(void) const {
  if (this->type() != NOTE_TYPES::NT_GNU_ABI_TAG) {
    return Note::UNKNOWN_VERSION;
  }

  const description_t& description = this->description();
  if (description.size() < (sizeof(uint32_t) + 3 * sizeof(uint32_t))) {
    LOG(WARNING) << "The description of the note seems corrupted";
    return Note::UNKNOWN_VERSION;
  }

  const uint32_t* version = reinterpret_cast<const uint32_t*>(description.data());
  return Note::version_t{{version[1], version[2], version[3]}};
}

bool Note::is_core(void) const {
  return this->is_core_;
}


bool Note::is_android(void) const {
  return this->name() == AndroidNote::NAME;
}

const NoteDetails& Note::details(void) const {
  return *(this->details_.second);
}

NoteDetails& Note::details(void) {
  NOTE_TYPES type = this->type();
  auto& dcache = this->details_;

  // already in cache
  if (dcache.first == type) {
    return *(dcache.second.get());
  }

  std::unique_ptr<NoteDetails> details(new NoteDetails());

  if (this->is_android()) {
    details.reset(new AndroidNote{AndroidNote::make(*this)});
  }

  if (this->is_core()) {
    NOTE_TYPES_CORE type_core = static_cast<NOTE_TYPES_CORE>(type);

    switch(type_core) {
      case NOTE_TYPES_CORE::NT_PRPSINFO:
        {
          details.reset(new CorePrPsInfo{CorePrPsInfo::make(*this)});
          break;
        }
      default:
        break;
    }
  }

  // update cache
  dcache.first = type;
  dcache.second.swap(details);
  return *dcache.second.get();
}

void Note::name(const std::string& name) {
  this->name_ = name;
}

void Note::type(NOTE_TYPES type) {
  this->type_ = type;
  this->is_core_ = false;
}

void Note::type_core(NOTE_TYPES_CORE type) {
  this->type_ = static_cast<NOTE_TYPES>(type);
  this->is_core_ = true;
  this->details();
}

void Note::description(const description_t& description) {
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
  visitor.visit(*this);
}


bool Note::operator==(const Note& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Note::operator!=(const Note& rhs) const {
  return not (*this == rhs);
}


void Note::dump(std::ostream& os) const {
  const description_t& description = this->description();

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
  os << std::setw(33) << std::setfill(' ') << "Name:" << this->name() << std::endl;
  const std::string type_str = this->is_core() ? to_string(this->type_core()) : to_string(this->type());
  os << std::setw(33) << std::setfill(' ') << "Type:" << type_str << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Description:" << description_str << std::endl;

  // early return if core
  if (this->is_core()) {
    this->details().dump(os);
    return;
  }

  // ABI TAG
  if (this->type() == NOTE_TYPES::NT_GNU_ABI_TAG) {
    Note::version_t version = this->version();
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


  // GOLD VERSION
  if (this->type() == NOTE_TYPES::NT_GNU_GOLD_VERSION) {
    std::string version_str{reinterpret_cast<const char*>(description.data()), description.size()};
    os << std::setw(33) << std::setfill(' ') << "Version:" << version_str << std::endl;
  }


  // BUILD ID
  if (this->type() == NOTE_TYPES::NT_GNU_BUILD_ID) {
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

}

std::ostream& operator<<(std::ostream& os, const Note& note) {
  note.dump(os);
  return os;

}

} // namespace ELF
} // namespace LIEF
