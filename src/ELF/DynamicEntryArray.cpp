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

DynamicEntryArray::DynamicEntryArray(const Elf64_Dyn* header) :
  DynamicEntry{header}
{}

DynamicEntryArray::DynamicEntryArray(const Elf32_Dyn* header) :
  DynamicEntry{header}
{}

std::vector<uint64_t>& DynamicEntryArray::array(void) {
  return const_cast<std::vector<uint64_t>&>(static_cast<const DynamicEntryArray*>(this)->array());
}


const std::vector<uint64_t>& DynamicEntryArray::array(void) const {
  return this->array_;
}

void DynamicEntryArray::array(const std::vector<uint64_t>& array) {
  this->array_ = array;
}

void DynamicEntryArray::accept(Visitor& visitor) const {
  DynamicEntry::accept(visitor);
  visitor(*this); // Double dispatch to avoid down-casting
  for (uint64_t x : this->array()) {
    visitor.visit(x);
  }
}

std::ostream& DynamicEntryArray::print(std::ostream& os) const {
  const std::vector<uint64_t>& array = this->array();
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
            return s.empty() ? ss.str() : " ," + ss.str();
         })
     << "]";


  return os;
}

}
}



