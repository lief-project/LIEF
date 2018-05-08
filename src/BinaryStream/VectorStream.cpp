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
#include <iterator>
#include <vector>
#include <string>
#include <fstream>
#include <cassert>
#include <sstream>
#include <algorithm>

#include "LIEF/logging++.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/exception.hpp"

VectorStream::VectorStream(const std::string& filename) {
  std::ifstream binary(filename, std::ios::in | std::ios::binary);

  if (binary) {
    binary.unsetf(std::ios::skipws);
    binary.seekg(0, std::ios::end);
    assert(binary.tellg() > 0);
    this->size_ = static_cast<uint64_t>(binary.tellg());
    binary.seekg(0, std::ios::beg);

    // reserve capacity
    this->binary_.resize(this->size() + 30, 0);
    std::copy(
      std::istreambuf_iterator<char>(binary),
      std::istreambuf_iterator<char>(),
      std::begin(this->binary_)
    );
    binary.close();
  } else {
    throw LIEF::bad_file("Unable to open " + filename);
  }
}


VectorStream::VectorStream(const std::vector<uint8_t>& data) :
  binary_{data},
  size_{data.size()}
{}


uint64_t VectorStream::size(void) const {
  return this->size_;
}


const void* VectorStream::read_at(uint64_t offset, uint64_t size, bool throw_error) const {

  if (offset > this->size() or (offset + size) > this->size()) {
    size_t out_size = (offset + size) - this->size();
    LOG(ERROR) << "Can't read "
               << std::dec << size << " bytes at "
               << std::hex << std::showbase << offset
               << " (" << std::hex << (out_size) << " bytes out of bound)";
    if (throw_error) {
      throw LIEF::read_out_of_bound(offset, size);
    }
    return nullptr;
  }
  return this->binary_.data() + offset;
}




const std::vector<uint8_t>& VectorStream::content(void) const {
  return this->binary_;
}

