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
#include <numeric>
#include <iomanip>

#include "LIEF/MachO/FatBinary.hpp"

namespace LIEF {
namespace MachO {

FatBinary::FatBinary(void) :
  binaries_{}
{}


FatBinary::FatBinary(const std::vector<Binary*>& binaries) :
  binaries_{binaries}
{}


size_t FatBinary::size(void) const {
  return this->binaries_.size();
}


it_binaries FatBinary::begin(void) {
  return this->binaries_;
}

it_const_binaries FatBinary::begin(void) const {
  return this->binaries_;
}


it_binaries FatBinary::end(void) {
  return it_binaries{this->binaries_}.end();
}

it_const_binaries FatBinary::end(void) const {
  return it_const_binaries{this->binaries_}.end();
}


Binary* FatBinary::pop_back(void) {
  if (this->binaries_.size() > 0) {
    Binary* last = this->binaries_.back();
    this->binaries_.pop_back();
    return last;
  }
  return nullptr;
}

Binary& FatBinary::at(size_t index) {
  return const_cast<Binary&>(static_cast<const FatBinary*>(this)->at(index));
}
const Binary& FatBinary::at(size_t index) const {
  if (index >= this->size()) {
    throw std::out_of_range("Bad index");
  }
  return *this->binaries_[index];
}


Binary& FatBinary::back(void) {
  return const_cast<Binary&>(static_cast<const FatBinary*>(this)->back());
}
const Binary& FatBinary::back(void) const {
  return *this->binaries_.back();
}

Binary& FatBinary::operator[](size_t index) {
  return const_cast<Binary&>(static_cast<const FatBinary*>(this)->operator[](index));
}

const Binary& FatBinary::operator[](size_t index) const {
  return this->at(index);
}


std::ostream& operator<<(std::ostream& os, const FatBinary& fatbinary) {
  for (const Binary& binary : fatbinary) {
    os << binary;
    os << std::endl << std::endl;
  }

  return os;
}

FatBinary::~FatBinary(void) {
  for (Binary* b : this->binaries_) {
    delete b;
  }
}


}
}
