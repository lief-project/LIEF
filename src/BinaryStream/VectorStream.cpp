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

#include "easylogging++.h"

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


const void* VectorStream::read(uint64_t offset, uint64_t size) const {

  if (offset > this->size() or (offset + size) > this->size()) {
    VLOG(VDEBUG) << "Offset: "      << std::hex << offset;
    VLOG(VDEBUG) << "Size: "        << std::hex << size;
    VLOG(VDEBUG) << "Binary Size: " << std::hex << this->size();

    if (offset > this->size()) {
      throw LIEF::read_out_of_bound(offset);
    }

    if ((offset + size) > this->size()) {
      throw LIEF::read_out_of_bound(offset, size);
    }
  }
  return this->binary_.data() + offset;

}


const char* VectorStream::read_string(uint64_t offset, uint64_t size) const {

  if ((offset + size) > this->size()) {
    throw LIEF::read_out_of_bound(offset);
  }


  uint64_t max_size = this->size() - (offset + size);
  if (size > 0) {
    max_size = std::min<uint64_t>(max_size, size);
  }

  return reinterpret_cast<const char*>(this->read(offset, max_size));
}

std::string VectorStream::get_string(uint64_t offset, uint64_t size) const {

  if ((offset + size) > this->size()) {
    throw LIEF::read_out_of_bound(offset);
  }

  size_t max_size = static_cast<size_t>(this->size() - (offset + size));
  if (size > 0) {
    max_size = std::min<size_t>(max_size, size);
  }
  const char* str = this->read_string(offset);
  const char* it_null = std::find(str, str + max_size, '\0');
  std::string tmp{str, it_null};
  return tmp.c_str();
}


const std::vector<uint8_t>& VectorStream::content(void) const {
  return this->binary_;
}

