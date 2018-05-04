
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

#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/hash.hpp"

namespace LIEF {
namespace DEX {

Class::Class(const Class&) = default;
Class& Class::operator=(const Class&) = default;

Class::Class(void) :
  fullname_{},
  access_flags_{ACCESS_FLAGS::ACC_UNKNOWN},
  parent_{nullptr},
  methods_{},
  source_filename_{},
  original_index_{-1u}
{}

Class::Class(const std::string& fullname,
      uint32_t access_flags,
      Class* parent,
      const std::string& source_filename) :
  fullname_{fullname},
  access_flags_{access_flags},
  parent_{parent},
  methods_{},
  source_filename_{source_filename},
  original_index_{-1u}
{}

std::string Class::package_normalized(const std::string& pkg) {
  std::string package_normalized = pkg;

  // 1. Remove the '/' at the end
  if (package_normalized.back() == '/') {
    package_normalized = package_normalized.substr(0, package_normalized.size() - 1);
  }

  // 2. Replace '.' with '/'
  std::replace(std::begin(package_normalized), std::end(package_normalized), '.', '/');
  return package_normalized;
}

std::string Class::fullname_normalized(const std::string& pkg, const std::string& cls_name) {
  return "L" + Class::package_normalized(pkg) + "/" + cls_name + ";";
}

std::string Class::fullname_normalized(const std::string& pkg_cls) {
  std::string package_normalized = pkg_cls;

  // 1. Replace '.' with '/'
  std::replace(std::begin(package_normalized), std::end(package_normalized), '.', '/');

  // 2. Add 'L' at the beginning
  if (package_normalized.front() != 'L') {
    package_normalized = 'L' + package_normalized;
  }

  // 3. Add ';' at the end
  if (package_normalized.back() != ';') {
    package_normalized = package_normalized + ';';
  }

  return package_normalized;
}

const std::string& Class::fullname(void) const {
  return this->fullname_;
}


std::string Class::package_name(void) const {
  size_t pos = this->fullname_.find_last_of('/');
  if (pos == std::string::npos) {
    return "";
  } else {
    return this->fullname_.substr(1, pos - 1);
  }
}

std::string Class::name(void) const {
  size_t pos = this->fullname_.find_last_of('/');
  if (pos == std::string::npos) {
    return this->fullname_.substr(1, this->fullname_.size() - 2);
  } else {
    return this->fullname_.substr(pos + 1, this->fullname_.size() - pos - 2);
  }
}

std::string Class::pretty_name(void) const {
  if (this->fullname_.size() <= 2) {
    return this->fullname_;
  }

  std::string pretty_name = this->fullname_.substr(1, this->fullname_.size() - 2);
  std::replace(std::begin(pretty_name), std::end(pretty_name), '/', '.');
  return pretty_name;

}


bool Class::has(ACCESS_FLAGS f) const {
  return (this->access_flags_ & f) > 0;
}

Class::access_flags_list_t Class::access_flags(void) const {

  Class::access_flags_list_t flags;

  std::copy_if(
      std::begin(access_flags_list),
      std::end(access_flags_list),
      std::back_inserter(flags),
      std::bind(static_cast<bool (Class::*)(ACCESS_FLAGS) const>(&Class::has), this, std::placeholders::_1));

  return flags;
}


bool Class::has_parent(void) const {
  return this->parent_ != nullptr;
}

const Class& Class::parent(void) const {
  if (not this->has_parent()) {
    throw not_found("No parent found!");
  }
  return *this->parent_;
}

Class& Class::parent(void) {
  return const_cast<Class&>(static_cast<const Class*>(this)->parent());
}

it_const_methods Class::methods(void) const {
  return this->methods_;
}

it_methods Class::methods(void) {
  return this->methods_;
}


it_methods Class::methods(const std::string& name) {
  return this->method_from_name(name);
}

it_const_methods Class::methods(const std::string& name) const {
  return this->method_from_name(name);
}

methods_t Class::method_from_name(const std::string& name) const {
  methods_t mtd;
  std::copy_if(
      std::begin(this->methods_),
      std::end(this->methods_),
      std::back_inserter(mtd),
      [name] (const Method* m) {
        return m->name() == name;
      });
  return mtd;
}

size_t Class::index(void) const {
  return this->original_index_;
}

const std::string& Class::source_filename(void) const {
  return this->source_filename_;
}

dex2dex_class_info_t Class::dex2dex_info(void) const {
  dex2dex_class_info_t info;
  for (Method* method : this->methods_) {
    if (method->dex2dex_info().size() > 0) {
      info.emplace(method, method->dex2dex_info());
    }
  }
  return info;
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
  os << cls.pretty_name();
  if (not cls.source_filename().empty()) {
    os << " - " << cls.source_filename();
  }

  os << " - " << std::dec << cls.methods().size() << " Methods";

  return os;
}

Class::~Class(void) = default;

}
}
