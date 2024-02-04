/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "pyLIEF.hpp"

namespace LIEF::py {
class PyIOStream : public VectorStream {
  public:
  static result<PyIOStream> from_python(nb::object object);
  PyIOStream() = delete;

  PyIOStream(const PyIOStream&) = delete;
  PyIOStream& operator=(const PyIOStream&) = delete;

  PyIOStream(PyIOStream&& other);
  PyIOStream& operator=(PyIOStream&& other);

  ~PyIOStream() override;

  protected:
  PyIOStream(nb::object io, std::vector<uint8_t> data);
  nb::object io_;
};
}

#endif
