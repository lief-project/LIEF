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
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include <numeric>
#include <sstream>
#include <iomanip>

namespace LIEF {
namespace ELF {

DynamicEntryArray::DynamicEntryArray(void) = default;
DynamicEntryArray& DynamicEntryArray::operator=(const DynamicEntryArray&) = default;
DynamicEntryArray::DynamicEntryArray(const DynamicEntryArray&) = default;


DynamicEntryArray::DynamicEntryArray(DYNAMIC_TAGS tag, const array_t& array) :
  DynamicEntry::DynamicEntry{tag, 0},
  array_{array}
{}


DynamicEntryArray::array_t& DynamicEntryArray::array(void) {
  return const_cast<DynamicEntryArray::array_t&>(static_cast<const DynamicEntryArray*>(this)->array());
}


const DynamicEntryArray::array_t& DynamicEntryArray::array(void) const {
  return this->array_;
}

void DynamicEntryArray::array(const DynamicEntryArray::array_t& array) {
  this->array_ = array;
}

DynamicEntryArray& DynamicEntryArray::append(uint64_t value) {
  this->array_.push_back(value);
  return *this;
}

DynamicEntryArray& DynamicEntryArray::remove(uint64_t callback) {
  this->array_.erase(std::remove_if(
        std::begin(this->array_),
        std::end(this->array_),
        [callback] (uint64_t v) {
          return v == callback;
        }), std::end(this->array_));
  return *this;
}

DynamicEntryArray& DynamicEntryArray::insert(size_t pos, uint64_t value) {
  if (pos == this->array_.size()) {
    return this->append(value);
  }

  if (pos > this->array_.size()) {
    throw corrupted(std::to_string(pos) + " is out of ranges");
  }
  this->array_.insert(std::begin(this->array_) + pos, value);
  return *this;
}


size_t DynamicEntryArray::size(void) const {
  return this->array_.size();
}

DynamicEntryArray& DynamicEntryArray::operator+=(uint64_t value) {
  return this->append(value);
}

DynamicEntryArray& DynamicEntryArray::operator-=(uint64_t value) {
  return this->remove(value);
}

const uint64_t& DynamicEntryArray::operator[](size_t idx) const {
  if (idx >= this->array_.size()) {
    throw corrupted(std::to_string(idx) + " is out of ranges");
  }
  return this->array_[idx];
}

uint64_t& DynamicEntryArray::operator[](size_t idx) {
  return const_cast<uint64_t&>(static_cast<const DynamicEntryArray*>(this)->operator[](idx));
}

void DynamicEntryArray::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& DynamicEntryArray::print(std::ostream& os) const {
  const DynamicEntryArray::array_t& array = this->array();
  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << "["
     << std::accumulate(
         std::begin(array),
         std::end(array),
         std::string(""),
         [] (std::string& s, uint64_t x) {
          std::stringstream ss;
          ss << "0x" << std::hex << x;
            return s.empty() ? ss.str() : s + ", " + ss.str();
         })
     << "]";


  return os;
}


DynamicEntryArray::~DynamicEntryArray(void) = default;

}
}



