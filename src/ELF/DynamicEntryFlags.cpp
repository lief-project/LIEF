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
#include <numeric>
#include <sstream>
#include <iomanip>

#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/EnumToString.hpp"

namespace LIEF {
namespace ELF {

DynamicEntryFlags::DynamicEntryFlags(void) = default;
DynamicEntryFlags& DynamicEntryFlags::operator=(const DynamicEntryFlags&) = default;
DynamicEntryFlags::DynamicEntryFlags(const DynamicEntryFlags&) = default;



bool DynamicEntryFlags::has(DYNAMIC_FLAGS f) const {
  if (this->tag() != DYNAMIC_TAGS::DT_FLAGS) {
    return false;
  }

  return (static_cast<uint64_t>(f) & this->value()) > 0;
}


bool DynamicEntryFlags::has(DYNAMIC_FLAGS_1 f) const {
  if (this->tag() != DYNAMIC_TAGS::DT_FLAGS_1) {
    return false;
  }
  return (static_cast<uint64_t>(f) & this->value()) > 0;
}

DynamicEntryFlags::flags_list_t DynamicEntryFlags::flags(void) const {
  DynamicEntryFlags::flags_list_t flags;


  if (this->tag() == DYNAMIC_TAGS::DT_FLAGS) {
    for (DYNAMIC_FLAGS f : dynamic_flags_array) {
      if (this->has(f)) {
        flags.insert(static_cast<uint32_t>(f));
      }
    }
  }

  if (this->tag() == DYNAMIC_TAGS::DT_FLAGS_1) {
    for (DYNAMIC_FLAGS_1 f : dynamic_flags_1_array) {
      if (this->has(f)) {
        flags.insert(static_cast<uint32_t>(f));
      }
    }
  }

  return flags;
}

void DynamicEntryFlags::add(DYNAMIC_FLAGS f) {
  if (this->tag() != DYNAMIC_TAGS::DT_FLAGS) {
    return;
  }

  this->value(this->value() | static_cast<uint64_t>(f));
}

void DynamicEntryFlags::add(DYNAMIC_FLAGS_1 f) {
  if (this->tag() != DYNAMIC_TAGS::DT_FLAGS_1) {
    return;
  }

  this->value(this->value() | static_cast<uint64_t>(f));
}

void DynamicEntryFlags::remove(DYNAMIC_FLAGS f) {
  if (this->tag() != DYNAMIC_TAGS::DT_FLAGS) {
    return;
  }

  this->value(this->value() & (~ static_cast<uint64_t>(f)));
}

void DynamicEntryFlags::remove(DYNAMIC_FLAGS_1 f) {
  if (this->tag() != DYNAMIC_TAGS::DT_FLAGS_1) {
    return;
  }

  this->value(this->value() & (~ static_cast<uint64_t>(f)));
}


DynamicEntryFlags& DynamicEntryFlags::operator+=(DYNAMIC_FLAGS f) {
  this->add(f);
  return *this;
}

DynamicEntryFlags& DynamicEntryFlags::operator+=(DYNAMIC_FLAGS_1 f) {
  this->add(f);
  return *this;
}

DynamicEntryFlags& DynamicEntryFlags::operator-=(DYNAMIC_FLAGS f) {
  this->remove(f);
  return *this;
}

DynamicEntryFlags& DynamicEntryFlags::operator-=(DYNAMIC_FLAGS_1 f) {
  this->remove(f);
  return *this;
}

void DynamicEntryFlags::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& DynamicEntryFlags::print(std::ostream& os) const {
  DynamicEntry::print(os);

  const flags_list_t& flags = this->flags();
  std::string flags_str = "";

  if (this->tag() == DYNAMIC_TAGS::DT_FLAGS) {
    flags_str = std::accumulate(
       std::begin(flags),
       std::end(flags), std::string{},
       [] (const std::string& a, const uint32_t flag) {
          DYNAMIC_FLAGS f = static_cast<DYNAMIC_FLAGS>(flag);
          return a.empty() ? to_string(f) : a + " - " + to_string(f);
       });
  }

  if (this->tag() == DYNAMIC_TAGS::DT_FLAGS_1) {
    flags_str = std::accumulate(
       std::begin(flags),
       std::end(flags), std::string{},
       [] (const std::string& a, const uint32_t flag) {
          DYNAMIC_FLAGS_1 f = static_cast<DYNAMIC_FLAGS_1>(flag);
          return a.empty() ? to_string(f) : a + " - " + to_string(f);
       });
  }

  os << " " << flags_str;

  return os;
}

}
}



