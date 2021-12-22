/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include <mbedtls/platform.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "logging.hpp"

#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/BinaryStream/MemoryStream.hpp"
#include "LIEF/exception.hpp"
namespace LIEF {


MemoryStream::MemoryStream(uintptr_t base_address) :
  baseaddr_{base_address},
  size_{-1llu}
{}

MemoryStream::MemoryStream(uintptr_t base_address, uint64_t size) :
  baseaddr_{base_address},
  size_{size}
{}

uint64_t MemoryStream::size() const {
  return this->size_;
}

const void* MemoryStream::read_at(uint64_t offset, uint64_t, bool) const {
  const uintptr_t va = this->baseaddr_ + offset;
  if (this->binary_ != nullptr) {
    return reinterpret_cast<const void*>(this->binary_->offset_to_virtual_address(offset, this->baseaddr_));
  }
  return reinterpret_cast<const void*>(va);
}

MemoryStream::~MemoryStream() = default;

}

