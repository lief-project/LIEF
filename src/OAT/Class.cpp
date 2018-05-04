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

#include "LIEF/OAT/Class.hpp"
#include "LIEF/OAT/Method.hpp"
#include "LIEF/OAT/hash.hpp"
#include "LIEF/OAT/EnumToString.hpp"

#include "LIEF/logging++.hpp"

#if defined(_MSC_VER)
#  include <intrin.h>
#  define __builtin_popcount __popcnt
#endif

namespace LIEF {
namespace OAT {

Class::Class(const Class&) = default;
Class& Class::operator=(const Class&) = default;

Class::Class(void) :
  dex_class_{nullptr},
  status_{OAT_CLASS_STATUS::STATUS_NOTREADY},
  type_{OAT_CLASS_TYPES::OAT_CLASS_NONE_COMPILED},
  method_bitmap_{},
  methods_{}
{}

Class::Class(OAT_CLASS_STATUS status,
      OAT_CLASS_TYPES type,
      DEX::Class* dex_class, const std::vector<uint32_t>& bitmap) :
  dex_class_{dex_class},
  status_{status},
  type_{type},
  method_bitmap_{bitmap},
  methods_{}
{}


bool Class::has_dex_class(void) const {
  return this->dex_class_ != nullptr;
}

const DEX::Class& Class::dex_class(void) const {
  if (not this->has_dex_class()) {
    throw not_found("No Dex Class associted with this OAT Class");
  }
  return *this->dex_class_;
}

DEX::Class& Class::dex_class(void) {
  return const_cast<DEX::Class&>(static_cast<const Class*>(this)->dex_class());
}

OAT_CLASS_STATUS Class::status(void) const {
  return this->status_;
}

OAT_CLASS_TYPES Class::type(void) const {
  return this->type_;
}

it_methods Class::methods(void) {
  return this->methods_;
}

it_const_methods Class::methods(void) const {
  return this->methods_;
}

DEX::dex2dex_class_info_t Class::dex2dex_info(void) const {
  return this->dex_class().dex2dex_info();
}


const std::string& Class::fullname(void) const {
  return this->dex_class().fullname();
}

size_t Class::index(void) const {
  if (this->has_dex_class()) {
    return this->dex_class().index();
  }
  return -1ull;
}

const std::vector<uint32_t>& Class::bitmap(void) const {
  return this->method_bitmap_;
}

bool Class::is_quickened(const DEX::Method& m) const {
  const DEX::Class& cls = this->dex_class();

  if (m.bytecode().size() == 0) {
    return false;
  }

  auto&& methods = cls.methods();
  auto&& it_method_index = std::find_if(
      std::begin(methods),
      std::end(methods),
      [&m] (const DEX::Method& mth) {
        return &m == &mth;
      });

  if (it_method_index == std::end(methods)) {
    LOG(ERROR) << "Can't find '" << m.name() << "' in " << cls.fullname();
    return false;
  }

  uint32_t relative_index = std::distance(std::begin(methods), it_method_index);
  return this->is_quickened(relative_index);

}

bool Class::is_quickened(uint32_t relative_index) const {
  if (this->type() == OAT_CLASS_TYPES::OAT_CLASS_NONE_COMPILED) {
    return false;
  }

  if (this->type() == OAT_CLASS_TYPES::OAT_CLASS_ALL_COMPILED) {
    return true;
  }

  if (this->type() == OAT_CLASS_TYPES::OAT_CLASS_SOME_COMPILED) {
    const uint32_t bitmap_idx  = relative_index >> 5;
    const uint32_t bitmap_mask = 1 << (relative_index & 0x1F);
    CHECK_LE(bitmap_idx, this->method_bitmap_.size());

    return (this->method_bitmap_[bitmap_idx] & bitmap_mask) != 0;
  }
  return false;
}

uint32_t Class::method_offsets_index(const DEX::Method& m) const {
  const DEX::Class& cls = this->dex_class();

  auto&& methods = cls.methods();
  auto&& it_method_index = std::find_if(
      std::begin(methods),
      std::end(methods),
      [&m] (const DEX::Method& mth) {
        return &m == &mth;
      });

  if (it_method_index == std::end(methods)) {
    LOG(ERROR) << "Can't find '" << m.name() << "' in " << cls.fullname();
    return -1u;
  }

  uint32_t relative_index = std::distance(std::begin(methods), it_method_index);
  return this->method_offsets_index(relative_index);
}

uint32_t Class::method_offsets_index(uint32_t relative_index) const {

  if (not this->is_quickened(relative_index) or this->type() == OAT_CLASS_TYPES::OAT_CLASS_NONE_COMPILED) {
    return -1u;
  }

  if (this->type() == OAT_CLASS_TYPES::OAT_CLASS_ALL_COMPILED) {
    return relative_index;
  }

  if (this->type() == OAT_CLASS_TYPES::OAT_CLASS_SOME_COMPILED) {
    const uint32_t bitmap_end_idx    = relative_index >> 5;
    const uint32_t partial_word_bits = relative_index & 0x1f;
    uint32_t count = 0;
    for (uint32_t word = 0; word < bitmap_end_idx; ++word) {
      count += __builtin_popcount(this->method_bitmap_[word]);
    }

    if (partial_word_bits != 0) {
      count += __builtin_popcount(this->method_bitmap_[bitmap_end_idx] & ~(0xffffffffu << partial_word_bits));
    }

    return count;
  }

  return -1u;
}

uint32_t Class::relative_index(const DEX::Method& m) const {
  const DEX::Class& cls = this->dex_class();

  auto&& methods = cls.methods();
  auto&& it_method_index = std::find_if(
      std::begin(methods),
      std::end(methods),
      [&m] (const DEX::Method& mth) {
        return &m == &mth;
      });

  if (it_method_index == std::end(methods)) {
    LOG(ERROR) << "Can't find '" << m.name() << "' in " << cls.fullname();
    return -1u;
  }

  return std::distance(std::begin(methods), it_method_index);
}

uint32_t Class::relative_index(uint32_t method_absolute_index) const {
  const DEX::Class& cls = this->dex_class();

  auto&& methods = cls.methods();
  auto&& it_method_index = std::find_if(
      std::begin(methods),
      std::end(methods),
      [method_absolute_index] (const DEX::Method& mth) {
        return mth.index() == method_absolute_index;
      });

  if (it_method_index == std::end(methods)) {
    LOG(ERROR) << "Can't find method with index #" << std::dec << method_absolute_index
               << " in " << cls.fullname();
    return -1u;
  }

  return std::distance(std::begin(methods), it_method_index);

}


void Class::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Class::operator==(const Class& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Class::operator!=(const Class& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Class& cls) {
  os << cls.fullname() << " - "
     << to_string(cls.status()) << " - "
     << to_string(cls.type()) << " - "
     << std::dec << cls.methods().size() << " methods";
  return os;
}

Class::~Class(void) = default;



}
}
