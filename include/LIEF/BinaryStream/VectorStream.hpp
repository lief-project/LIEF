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
#ifndef VECTOR_BINARY_STREAM_H
#define VECTOR_BINARY_STREAM_H

#include <vector>
#include <string>

#include "LIEF/BinaryStream/BinaryStream.hpp"

class VectorStream : public BinaryStream {
  public:
  //using BinaryStream::read_integer;
  VectorStream(const std::string& filename);
  VectorStream(const std::vector<uint8_t>& data);

  virtual uint64_t size(void) const override;

  const std::vector<uint8_t>& content(void) const;

  protected:
  virtual const void* read_at(uint64_t offset, uint64_t size, bool throw_error = true) const override;
  std::vector<uint8_t> binary_;
  uint64_t size_;
};


#endif
