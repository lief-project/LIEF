/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <ostream>
#include "LIEF/Visitor.hpp"

#include "LIEF/Abstract/Function.hpp"

namespace LIEF {
Function::Function() = default;
Function::Function(const Function&) = default;
Function& Function::operator=(const Function&) = default;
Function::~Function() = default;

Function::Function(uint64_t address) :
  Symbol{"", address}
{}

Function::Function(const std::string& name) :
  Symbol{name}
{}

Function::Function(const std::string& name, uint64_t address) :
  Symbol{name, address}
{}

Function::Function(const std::string& name, uint64_t address, const Function::flags_list_t& flags) :
  Symbol{name, address},
  flags_{std::begin(flags), std::end(flags)}
{}


uint64_t Function::address() const {
  return value_;
}

void Function::address(uint64_t address) {
  value_ = address;
}

Function::flags_list_t Function::flags() const {
  return {std::begin(flags_), std::end(flags_)};
}

Function& Function::add(Function::FLAGS f) {
  flags_.insert(f);
  return *this;
}

void Function::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Function& entry) {
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
  if (!name.empty()) {
    os << name;
  }

  if (entry.address() > 0) {
    os << std::hex << std::left << std::showbase << " - " << entry.address();
  }

  if (entry.size() > 0) {
    os << " (" << std::dec << entry.size() << " bytes)";
  }


  return os;
}
}

