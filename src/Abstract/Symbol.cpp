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
#include <algorithm>
#include <iostream>

#include "LIEF/Abstract/Symbol.hpp"

namespace LIEF {
Symbol::Symbol(void) = default;
Symbol::Symbol(const Symbol&) = default;
Symbol& Symbol::operator=(const Symbol&) = default;
Symbol::~Symbol(void) = default;

Symbol::Symbol(const std::string& name) :
  name_{name}
{}

const std::string& Symbol::name(void) const {
  return this->name_;
}

void Symbol::name(const std::string& name) {
  this->name_ = name;
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
      (unsigned char c) { return (c < 127 and c > 32) ? c : ' ';});
  if (name.size() > 20) {
    name = name.substr(0, 17) + "...";
  }
  os << name;

  return os;
}
}

