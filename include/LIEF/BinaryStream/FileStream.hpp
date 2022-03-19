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
#ifndef LIEF_FILE_STREAM_H
#define LIEF_FILE_STREAM_H

#include <fstream>
#include <string>
#include <vector>

#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/errors.hpp"
namespace LIEF {

//! Stream interface over a std::ifstream
class FileStream : public BinaryStream {
 public:
  static result<FileStream> from_file(const std::string& file);
  FileStream(std::ifstream fs, uint64_t size);

  FileStream() = delete;

  // VectorStream should not be copyable for performances reasons
  FileStream(const FileStream&) = delete;
  FileStream& operator=(const FileStream&) = delete;

  FileStream(FileStream&& other);
  FileStream& operator=(FileStream&& other);

  inline uint64_t size() const override { return size_; }

  std::vector<uint8_t> content() const;
  ~FileStream() override;

  static bool classof(const BinaryStream& stream);

 protected:
  inline ok_error_t peek_in(void* dst, uint64_t offset,
                            uint64_t size) const override {
    if (offset > size_ || offset + size > size_) {
      return make_error_code(lief_errors::read_error);
    }
    const auto pos = ifs_.tellg();
    ifs_.seekg(offset);
    ifs_.read(static_cast<char*>(dst), size);
    ifs_.seekg(pos);
    return ok();
  }
  inline result<const void*> read_at(uint64_t, uint64_t) const override {
    return make_error_code(lief_errors::not_supported);
  }
  mutable std::ifstream ifs_;
  uint64_t size_ = 0;
};
}  // namespace LIEF

#endif
