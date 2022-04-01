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
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/exception.hpp"
#include "logging.hpp"

#include <numeric>
#include <sstream>
#include <iomanip>
#include <utility>

namespace LIEF {
namespace ELF {

DynamicEntryArray::DynamicEntryArray() = default;
DynamicEntryArray& DynamicEntryArray::operator=(const DynamicEntryArray&) = default;
DynamicEntryArray::DynamicEntryArray(const DynamicEntryArray&) = default;


DynamicEntryArray::DynamicEntryArray(DYNAMIC_TAGS tag, array_t array) :
  DynamicEntry::DynamicEntry{tag, 0},
  array_{std::move(array)}
{}


DynamicEntryArray::array_t& DynamicEntryArray::array() {
  return const_cast<DynamicEntryArray::array_t&>(static_cast<const DynamicEntryArray*>(this)->array());
}


const DynamicEntryArray::array_t& DynamicEntryArray::array() const {
  return array_;
}

void DynamicEntryArray::array(const DynamicEntryArray::array_t& array) {
  array_ = array;
}

DynamicEntryArray& DynamicEntryArray::append(uint64_t function) {
  array_.push_back(function);
  return *this;
}

DynamicEntryArray& DynamicEntryArray::remove(uint64_t function) {
  array_.erase(std::remove_if(std::begin(array_), std::end(array_),
                              [function] (uint64_t v) { return v == function; }),
               std::end(array_));
  return *this;
}

DynamicEntryArray& DynamicEntryArray::insert(size_t pos, uint64_t function) {
  if (pos == array_.size()) {
    return append(function);
  }

  if (pos > array_.size()) {
    LIEF_ERR("pos: {:d} is out of range", pos);
    return *this;
  }

  array_.insert(std::begin(array_) + pos, function);
  return *this;
}


size_t DynamicEntryArray::size() const {
  return array_.size();
}

DynamicEntryArray& DynamicEntryArray::operator+=(uint64_t value) {
  return append(value);
}

DynamicEntryArray& DynamicEntryArray::operator-=(uint64_t value) {
  return remove(value);
}

const uint64_t& DynamicEntryArray::operator[](size_t idx) const {
  static uint64_t GARBAGE;
  if (idx >= array_.size()) {
    LIEF_WARN("DynamicEntryArray[{}] is out-of-range", idx);
    return GARBAGE;
  }
  return array_[idx];
}

uint64_t& DynamicEntryArray::operator[](size_t idx) {
  return const_cast<uint64_t&>(static_cast<const DynamicEntryArray*>(this)->operator[](idx));
}

void DynamicEntryArray::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool DynamicEntryArray::classof(const DynamicEntry* entry) {
  const DYNAMIC_TAGS tag = entry->tag();
  return tag == DYNAMIC_TAGS::DT_INIT_ARRAY ||
         tag == DYNAMIC_TAGS::DT_FINI_ARRAY ||
         tag == DYNAMIC_TAGS::DT_PREINIT_ARRAY;
}

std::ostream& DynamicEntryArray::print(std::ostream& os) const {
  const DynamicEntryArray::array_t& array = this->array();
  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << "["
     << std::accumulate(std::begin(array), std::end(array), std::string(),
         [] (std::string& s, uint64_t x) {
          std::stringstream ss;
          ss << "0x" << std::hex << x;
            return s.empty() ? ss.str() : s + ", " + ss.str();
         })
     << "]";


  return os;
}


DynamicEntryArray::~DynamicEntryArray() = default;

}
}



