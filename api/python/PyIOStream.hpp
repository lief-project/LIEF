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
#ifndef LIEF_PY_IO_STREAM_H
#define LIEF_PY_IO_STREAM_H

#include <string>
#include <vector>

#include "LIEF/errors.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "pyLIEF.hpp"

namespace LIEF {
class PyIOStream : public BinaryStream {
  public:
  static result<PyIOStream> from_python(py::object object);
  PyIOStream() = delete;

  PyIOStream(const PyIOStream&) = delete;
  PyIOStream& operator=(const PyIOStream&) = delete;

  PyIOStream(PyIOStream&& other);
  PyIOStream& operator=(PyIOStream&& other);

  inline uint64_t size() const override {
    return data_.size();
  }

  ~PyIOStream() override;

  protected:
  PyIOStream(py::object io);
  //ok_error_t peek_in(void* dst, uint64_t offset, uint64_t size) const override;

  result<const void*> read_at(uint64_t offset, uint64_t size) const override;
  py::object io_;
  std::vector<uint8_t> data_;
};
}

#endif
