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
#include <algorithm>
#include <iostream>

#include "LIEF/Abstract/Symbol.hpp"

namespace LIEF {
Symbol::Symbol() = default;
Symbol::Symbol(const Symbol&) = default;
Symbol& Symbol::operator=(const Symbol&) = default;
Symbol::~Symbol() = default;

Symbol::Symbol(std::string name) :
  name_{std::move(name)}
{}

Symbol::Symbol(std::string name, uint64_t value) :
  name_{std::move(name)},
  value_{value}
{}

Symbol::Symbol(std::string name, uint64_t value, uint64_t size) :
  name_{std::move(name)},
  value_{value},
  size_{size}
{}

void Symbol::swap(Symbol& other) {
  std::swap(name_,   other.name_);
  std::swap(value_,  other.value_);
  std::swap(size_,   other.size_);
}

const std::string& Symbol::name() const {
  return name_;
}

std::string& Symbol::name() {
  return name_;
}

void Symbol::name(const std::string& name) {
  name_ = name;
}

uint64_t Symbol::value() const {
  return value_;
}

void Symbol::value(uint64_t value) {
  value_ = value;
}

uint64_t Symbol::size() const {
  return size_;
}

void Symbol::size(uint64_t value) {
  size_ = value;
}


void Symbol::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Symbol& entry) {
  std::string name = entry.name();
  // UTF8 -> ASCII
  std::transform(
      std::begin(name),
      std::end(name),
      std::begin(name), []
      (unsigned char c) { return (c < 127 && c > 32) ? c : ' ';});
  if (name.size() > 20) {
    name = name.substr(0, 17) + "...";
  }
  os << name;

  return os;
}
}

