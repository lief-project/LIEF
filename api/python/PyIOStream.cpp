/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include "PyIOStream.hpp"
#include "logging.cpp"

namespace LIEF {
PyIOStream::PyIOStream(PyIOStream&& other) = default;
PyIOStream& PyIOStream::operator=(PyIOStream&& other) = default;

result<PyIOStream> PyIOStream::from_python(py::object object) {
  py::module_ mod_io;
  py::object IOBase;
  if (!mod_io) {
    mod_io = py::module::import("io");
  }

  if (!IOBase) {
    IOBase = mod_io.attr("IOBase");
  }

  if (!py::isinstance(object, IOBase)) {
    LIEF_ERR("The provided io object does not sub-class io.IOBase");
    return make_error_code(lief_errors::read_error);
  }

  if (!py::hasattr(object, "tell")) {
    LIEF_ERR("The provided io object does not implement tell() from io.IOBase");
    return make_error_code(lief_errors::read_error);
  }

  if (!py::hasattr(object, "seek")) {
    LIEF_ERR("The provided io object does not implement tell() from io.IOBase");
    return make_error_code(lief_errors::read_error);
  }


  if (!py::hasattr(object, "read") && !py::hasattr(object, "readinto")) {
    LIEF_ERR("The provided io object does not implement read() or readinto()");
    return make_error_code(lief_errors::read_error);
  }

  return PyIOStream(object);
}

PyIOStream::PyIOStream(py::object io) : io_{io} {
  static constexpr int PY_SEEK_SET = 0;
  static constexpr int PY_SEEK_END = 2;
  auto seek = io.attr("seek");
  seek(0, PY_SEEK_SET);
  seek(0, PY_SEEK_END);
  const size_t size = io.attr("tell")().cast<size_t>();
  data_.resize(size);

  seek(0, PY_SEEK_SET);
  if (py::hasattr(io_, "readinto")) {
    auto view = py::memoryview::from_memory(data_.data(), size);
    io_.attr("readinto")(view);
  }
  else if (py::hasattr(io_, "read")) {
    py::bytes content = io_.attr("read")(size);
    std::string buffer = std::move(content);
    std::move(std::begin(buffer), std::end(buffer), data_.data());
  }
  seek(0, PY_SEEK_SET);
}

result<const void*> PyIOStream::read_at(uint64_t offset, uint64_t size) const {
  const uint64_t stream_size = this->size();
  if (offset > stream_size || (offset + size) > stream_size) {
    size_t out_size = (offset + size) - stream_size;
    LIEF_DEBUG("Can't read #{:d} bytes at 0x{:04x} (0x{:x} bytes out of bound)", size, offset, out_size);
    return make_error_code(lief_errors::read_error);
  }
  return data_.data() + offset;
}


PyIOStream::~PyIOStream() = default;
}
