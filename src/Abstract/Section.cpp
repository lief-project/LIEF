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
#include <array>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <iomanip>

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/Abstract/Section.hpp"

namespace LIEF {
Section::Section(void) :
  name_{""},
  virtual_address_{0},
  size_{0},
  offset_{0}
{}


Section::~Section(void) = default;
Section& Section::operator=(const Section& copy) = default;
Section::Section(const Section& copy) = default;

const std::string& Section::name(void) const {
  return this->name_;
}


void Section::name(const std::string& name) {
  this->name_ = name;
}


void Section::content(const std::vector<uint8_t>&) {
  throw not_supported("Not supported by this format");
}


std::vector<uint8_t> Section::content(void) const {
  throw not_supported("Not supported by this format");
}


uint64_t Section::size(void) const {
  return this->size_;
}


void Section::size(uint64_t size) {
  this->size_ = size;
}



uint64_t Section::offset(void) const {
  return this->offset_;
}


uint64_t Section::virtual_address(void) const {
  return this->virtual_address_;
}

void Section::virtual_address(uint64_t virtual_address) {
  this->virtual_address_ = virtual_address;;
}

void Section::offset(uint64_t offset) {
  this->offset_ = offset;
}


double Section::entropy(void) const {
  std::array<uint64_t, 256> frequencies = { {0} };
  const std::vector<uint8_t>& content = this->content();
  for (uint8_t x : content) {
    frequencies[x]++;
  }

  double entropy = 0.0;
  for (uint64_t p : frequencies) {
    if (p > 0) {
      double freq = static_cast<double>(p) / static_cast<double>(content.size());
      entropy += freq * std::log2(freq) ;
    }
  }
  return (-entropy);
}


void Section::accept(Visitor& visitor) const {
  visitor.visit(this->name());
  visitor.visit(this->virtual_address());
  visitor.visit(this->offset());
  visitor.visit(this->size());
}


bool Section::operator==(const Section& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Section::operator!=(const Section& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Section& entry) {
  os << std::hex;
  os << std::left
     << std::setw(30) << entry.name()
     << std::setw(10) << entry.virtual_address()
     << std::setw(10) << entry.size()
     << std::setw(10) << entry.offset()
     << std::setw(10) << entry.entropy();

  return os;
}

}
