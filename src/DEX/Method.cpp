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

#include "LIEF/DEX/Method.hpp"
#include "LIEF/DEX/Class.hpp"
#include "LIEF/logging++.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/DEX/enums.hpp"
#include "LIEF/DEX/EnumToString.hpp"

#include <numeric>


namespace LIEF {
namespace DEX {

Method::Method(const Method&) = default;
Method& Method::operator=(const Method&) = default;

Method::Method(void) :
  name_{},
  parent_{nullptr},
  access_flags_{ACCESS_FLAGS::ACC_UNKNOWN},
  original_index_{-1u},
  code_offset_{0},
  bytecode_{},
  code_info_{},
  dex2dex_info_{}
{}

Method::Method(const std::string& name, Class* parent) :
  name_{name},
  parent_{parent},
  access_flags_{ACCESS_FLAGS::ACC_UNKNOWN},
  original_index_{-1u},
  code_offset_{0},
  bytecode_{},
  code_info_{},
  dex2dex_info_{}
{}

const std::string& Method::name(void) const {
  return this->name_;
}

uint64_t Method::code_offset(void) const {
  return this->code_offset_;
}

const Method::bytecode_t& Method::bytecode(void) const {
  return this->bytecode_;
}

bool Method::has_class(void) const {
  return this->parent_ != nullptr;
}

const Class& Method::cls(void) const {
  if (not this->has_class()) {
    throw not_found("Can't find class associated with " + this->name());
  }
  return *this->parent_;
}

Class& Method::cls(void) {
  return const_cast<Class&>(static_cast<const Method*>(this)->cls());
}

size_t Method::index(void) const {
  return this->original_index_;
}

void Method::insert_dex2dex_info(uint32_t pc, uint32_t index) {
  this->dex2dex_info_.emplace(pc, index);
}

const dex2dex_method_info_t& Method::dex2dex_info(void) const {
  return this->dex2dex_info_;
}

bool Method::is_virtual(void) const {
  return this->is_virtual_;
}

void Method::set_virtual(bool v) {
  this->is_virtual_ = v;
}


bool Method::has(ACCESS_FLAGS f) const {
  return (this->access_flags_ & f);
}

Method::access_flags_list_t Method::access_flags(void) const {
  Method::access_flags_list_t flags;

  std::copy_if(
      std::begin(access_flags_list),
      std::end(access_flags_list),
      std::back_inserter(flags),
      std::bind(static_cast<bool (Method::*)(ACCESS_FLAGS) const>(&Method::has), this, std::placeholders::_1));

  return flags;

}

const Prototype& Method::prototype(void) const {
  CHECK_NE(this->prototype_, nullptr);
  return *this->prototype_;
}

Prototype& Method::prototype(void) {
  return const_cast<Prototype&>(static_cast<const Method*>(this)->prototype());
}

void Method::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Method::operator==(const Method& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Method::operator!=(const Method& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Method& method) {
  Prototype::it_const_params ps = method.prototype().parameters_type();
  std::string pretty_cls_name = method.cls().fullname();
  if (not pretty_cls_name.empty()) {
    pretty_cls_name = pretty_cls_name.substr(1, pretty_cls_name.size() - 2);
    std::replace(std::begin(pretty_cls_name), std::end(pretty_cls_name), '/', '.');
  }

  Method::access_flags_list_t aflags = method.access_flags();
  std::string flags_str = std::accumulate(
      std::begin(aflags),
      std::end(aflags),
      std::string{},
      [] (const std::string& l, ACCESS_FLAGS r) {
        std::string str = to_string(r);
        std::transform(std::begin(str), std::end(str), std::begin(str), ::tolower);
        return l.empty() ? str : l + " " + str;
      });

  if (not flags_str.empty()) {
    os << flags_str << " ";
  }
  os << method.prototype().return_type()
     << " "
     << pretty_cls_name << "->" << method.name();

  os << "(";
  for (size_t i = 0; i < ps.size(); ++i) {
    if (i > 0) {
      os << ", ";
    }
    os << ps[i] << " p" << std::dec << i;
  }
  os << ")";

  return os;
}

Method::~Method(void) = default;

}
}
