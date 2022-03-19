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
#include "LIEF/Abstract/Section.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <utility>

#include "LIEF/Abstract/hash.hpp"
#include "LIEF/exception.hpp"
#include "Section.tcc"
#include "logging.hpp"

namespace LIEF {

Section::Section() = default;

Section::Section(std::string name) : name_{std::move(name)} {}

Section::~Section() = default;
Section& Section::operator=(const Section&) = default;
Section::Section(const Section&) = default;

std::string Section::name() const { return name_.c_str(); }

const std::string& Section::fullname() const { return name_; }

void Section::name(const std::string& name) { name_ = name; }

void Section::content(const std::vector<uint8_t>&) {
  LIEF_ERR("Not supported by this format");
}

span<const uint8_t> Section::content() const {
  LIEF_ERR("Not supported by this format");
  return {};
}

uint64_t Section::size() const { return size_; }

void Section::size(uint64_t size) { size_ = size; }

uint64_t Section::offset() const { return offset_; }

uint64_t Section::virtual_address() const { return virtual_address_; }

void Section::virtual_address(uint64_t virtual_address) {
  virtual_address_ = virtual_address;
  ;
}

void Section::offset(uint64_t offset) { offset_ = offset; }

// Search functions
// ================
size_t Section::search(uint64_t integer, size_t pos, size_t size) const {
  if (size > sizeof(integer)) {
    throw std::runtime_error("Invalid size (" + std::to_string(size) + ")");
  }

  size_t minimal_size = size;
  if (size == 0) {
    if (integer < std::numeric_limits<uint8_t>::max()) {
      minimal_size = sizeof(uint8_t);
    } else if (integer < std::numeric_limits<uint16_t>::max()) {
      minimal_size = sizeof(uint16_t);
    } else if (integer < std::numeric_limits<uint32_t>::max()) {
      minimal_size = sizeof(uint32_t);
    } else if (integer < std::numeric_limits<uint64_t>::max()) {
      minimal_size = sizeof(uint64_t);
    } else {
      throw exception("Unable to find an appropriated type of " +
                      std::to_string(integer));
    }
  }

  std::vector<uint8_t> pattern(minimal_size, 0);

  std::copy(reinterpret_cast<const uint8_t*>(&integer),
            reinterpret_cast<const uint8_t*>(&integer) + minimal_size,
            pattern.data());

  return search(pattern, pos);
}

size_t Section::search(const std::vector<uint8_t>& pattern, size_t pos) const {
  span<const uint8_t> content = this->content();

  const auto it_found =
      std::search(std::begin(content) + pos, std::end(content),
                  std::begin(pattern), std::end(pattern));

  if (it_found == std::end(content)) {
    return Section::npos;
  }

  return std::distance(std::begin(content), it_found);
}

size_t Section::search(const std::string& pattern, size_t pos) const {
  std::vector<uint8_t> pattern_formated = {std::begin(pattern),
                                           std::end(pattern)};
  return search(pattern_formated, pos);
}

size_t Section::search(uint64_t integer, size_t pos) const {
  return search(integer, pos, 0);
}

// Search all functions
// ====================
std::vector<size_t> Section::search_all(uint64_t v, size_t size) const {
  std::vector<size_t> result;
  size_t pos = search(v, 0, size);

  if (pos == Section::npos) {
    return result;
  }

  do {
    result.push_back(pos);
    pos = search(v, pos + 1, size);
  } while (pos != Section::npos);

  return result;
}

std::vector<size_t> Section::search_all(uint64_t v) const {
  return search_all(v, 0);
}

std::vector<size_t> Section::search_all(const std::string& v) const {
  return search_all_<std::string>(v);
}

double Section::entropy() const {
  std::array<uint64_t, 256> frequencies = {{0}};
  span<const uint8_t> content = this->content();
  if (content.size() == 0) {
    return 0.;
  }
  for (uint8_t x : content) {
    frequencies[x]++;
  }

  double entropy = 0.0;
  for (uint64_t p : frequencies) {
    if (p > 0) {
      double freq =
          static_cast<double>(p) / static_cast<double>(content.size());
      entropy += freq * std::log2l(freq);
    }
  }
  return (-entropy);
}

void Section::accept(Visitor& visitor) const { visitor.visit(*this); }

bool Section::operator==(const Section& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = AbstractHash::hash(*this);
  size_t hash_rhs = AbstractHash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Section::operator!=(const Section& rhs) const { return !(*this == rhs); }

std::ostream& operator<<(std::ostream& os, const Section& entry) {
  os << std::hex;
  os << std::left << std::setw(30) << entry.name() << std::setw(10)
     << entry.virtual_address() << std::setw(10) << entry.size()
     << std::setw(10) << entry.offset() << std::setw(10) << entry.entropy();

  return os;
}

}  // namespace LIEF
