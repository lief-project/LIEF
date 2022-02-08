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
#include <memory>
#include <numeric>
#include <sstream>
#include <algorithm>
#include <utility>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "logging.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails.hpp"
#include "LIEF/ELF/NoteDetails/AndroidNote.hpp"
#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreAuxv.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"

namespace LIEF {
namespace ELF {

Note::~Note() = default;

Note& Note::operator=(Note other) {
  swap(other);
  return *this;
}

Note::Note(const Note& other):
  Object(other),
  binary_(other.binary_),
  name_(other.name_),
  type_(other.type_),
  description_(other.description_)
{
  const auto& details = other.details_;
  details_ = std::make_pair(details.first, std::unique_ptr<NoteDetails>{details.second->clone()});
}

void Note::swap(Note& other) {
  std::swap(binary_,      other.binary_);
  std::swap(name_,        other.name_);
  std::swap(type_,        other.type_);
  std::swap(description_, other.description_);
  std::swap(details_,     other.details_);
}

Note::Note() :
  type_{NOTE_TYPES::NT_UNKNOWN},
  details_{std::make_pair(NOTE_TYPES::NT_UNKNOWN, std::make_unique<NoteDetails>())}
{}

Note::Note(std::string name, uint32_t type, description_t description, Binary* binary):
  binary_{binary},
  name_{std::move(name)},
  type_{static_cast<NOTE_TYPES>(type)},
  description_{std::move(description)},
  details_{std::make_pair(NOTE_TYPES::NT_UNKNOWN, std::make_unique<NoteDetails>())}
{}

Note::Note(const std::string& name, NOTE_TYPES type, const description_t& description, Binary* binary):
  Note::Note{name, static_cast<uint32_t>(type), description, binary}
{}

Note::Note(const std::string& name, NOTE_TYPES_CORE type, const description_t& description, Binary* binary):
  Note::Note{name, static_cast<uint32_t>(type), description, binary}
{
  is_core_ = true;
  details();
}


const std::string& Note::name() const {
  return name_;
}

NOTE_TYPES Note::type() const {
  return type_;
}

NOTE_TYPES_CORE Note::type_core() const {
  return static_cast<NOTE_TYPES_CORE>(type_);
}

const Note::description_t& Note::description() const {
  return description_;
}

Note::description_t& Note::description() {
  return description_;
}

bool Note::is_core() const {
  return is_core_;
}


bool Note::is_android() const {
  return name() == AndroidNote::NAME;
}

const NoteDetails& Note::details() const {
  return *(details_.second);
}

NoteDetails& Note::details() {
  NOTE_TYPES type = this->type();
  auto& dcache = details_;

  // already in cache
  if (dcache.first == type) {
    return *(dcache.second);
  }

  std::unique_ptr<NoteDetails> details = nullptr;

  if (is_android()) {
    details = std::make_unique<AndroidNote>(AndroidNote::make(*this));
  }

  if (is_core()) {
    auto type_core = static_cast<NOTE_TYPES_CORE>(type);

    switch(type_core) {
      case NOTE_TYPES_CORE::NT_PRPSINFO:
        {
          details = std::make_unique<CorePrPsInfo>(CorePrPsInfo::make(*this));
          break;
        }

      case NOTE_TYPES_CORE::NT_FILE:
        {
          details = std::make_unique<CoreFile>(CoreFile::make(*this));
          break;
        }

      case NOTE_TYPES_CORE::NT_PRSTATUS:
        {
          details = std::make_unique<CorePrStatus>(CorePrStatus::make(*this));
          break;
        }

      case NOTE_TYPES_CORE::NT_AUXV:
        {
          details = std::make_unique<CoreAuxv>(CoreAuxv::make(*this));
          break;
        }

      case NOTE_TYPES_CORE::NT_SIGINFO:
        {
          details = std::make_unique<CoreSigInfo>(CoreSigInfo::make(*this));
          break;
        }

      default:
        break;
    }
  }

  if (!details) {
    switch (type) {
      case NOTE_TYPES::NT_GNU_ABI_TAG:
        {
          details = std::make_unique<NoteAbi>(NoteAbi::make(*this));
          break;
        }

      default:
        {
          details = std::make_unique<NoteDetails>();
          break;
        }
    }
  }

  // update cache
  dcache.first = type;
  dcache.second.swap(details);
  return *dcache.second;
}

void Note::name(const std::string& name) {
  name_ = name;
}

void Note::type(NOTE_TYPES type) {
  type_ = type;
  is_core_ = false;
}

void Note::type_core(NOTE_TYPES_CORE type) {
  type_ = static_cast<NOTE_TYPES>(type);
  is_core_ = true;
  details();
}

void Note::description(const description_t& description) {
  description_ = description;
}

uint64_t Note::size() const {
  uint64_t size = 0;
  size += 3 * sizeof(uint32_t);
  size += name().size() + 1;
  size = align(size, sizeof(uint32_t));
  size += description().size();
  size = align(size, sizeof(uint32_t));
  return size;
}

void Note::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Note::operator==(const Note& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Note::operator!=(const Note& rhs) const {
  return !(*this == rhs);
}


void Note::dump(std::ostream& os) const {
  const description_t& desc = description();

  std::string description_str = std::accumulate(
      std::begin(desc),
      std::begin(desc) + std::min<size_t>(16, desc.size()), std::string{},
      [] (const std::string& a, uint8_t v) {
        std::ostringstream hex_v;
        hex_v << std::setw(2) << std::setfill('0') << std::hex;
        hex_v << static_cast<uint32_t>(v);

        return a.empty() ? "[" + hex_v.str() : a + " " + hex_v.str();
      });
  if (desc.size() > 16) {
    description_str += " ...";
  }
  description_str += "]";
  os << std::hex << std::left;
  os << std::setw(33) << std::setfill(' ') << "Name:" << name() << std::endl;
  const std::string type_str = is_core() ? to_string(type_core()) : to_string(type());
  os << std::setw(33) << std::setfill(' ') << "Type:" << type_str << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Description:" << description_str << std::endl;

  if (!is_core()) {
    // GOLD VERSION
    if (type() == NOTE_TYPES::NT_GNU_GOLD_VERSION) {
      std::string version_str{reinterpret_cast<const char*>(desc.data()), desc.size()};
      os << std::setw(33) << std::setfill(' ') << "Version:" << version_str << std::endl;
    }

    // BUILD ID
    if (type() == NOTE_TYPES::NT_GNU_BUILD_ID) {
      std::string hash = std::accumulate(std::begin(desc), std::end(desc), std::string{},
        [] (const std::string& a, uint8_t v) {
          std::ostringstream hex_v;
          hex_v << std::setw(2) << std::setfill('0') << std::hex;
          hex_v << static_cast<uint32_t>(v);

          return a + hex_v.str();
        });

      os << std::setw(33) << std::setfill(' ') << "ID Hash:" << hash << std::endl;
    }
  }

  details().dump(os);
}

std::ostream& operator<<(std::ostream& os, const Note& note) {
  note.dump(os);
  return os;

}

} // namespace ELF
} // namespace LIEF
