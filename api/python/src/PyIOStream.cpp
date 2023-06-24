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
#include "LIEF/logging.hpp"

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
    logging::log(logging::LOGGING_LEVEL::LOG_ERR, "The provided io object does not sub-class io.IOBase");
    return make_error_code(lief_errors::read_error);
  }

  if (!py::hasattr(object, "read") && !py::hasattr(object, "readinto")) {
    logging::log(logging::LOGGING_LEVEL::LOG_ERR, "The provided io object does not implement read() or readinto()");
    return make_error_code(lief_errors::read_error);
  }

  static constexpr int PY_SEEK_SET = 0;
  static constexpr int PY_SEEK_END = 2;
  auto seek = object.attr("seek");
  seek(0, PY_SEEK_SET);
  seek(0, PY_SEEK_END);
  const size_t size = object.attr("tell")().cast<size_t>();
  std::vector<uint8_t> data;
  data.resize(size);

  seek(0, PY_SEEK_SET);
  if (py::hasattr(object, "readinto")) {
    auto view = py::memoryview::from_memory(data.data(), size);
    object.attr("readinto")(view);
  }
  else if (py::hasattr(object, "read")) {
    py::bytes content = object.attr("read")(size);
    std::string buffer = std::move(content);
    std::move(std::begin(buffer), std::end(buffer), data.data());
  }
  seek(0, PY_SEEK_SET);

  return PyIOStream(object, std::move(data));
}

PyIOStream::PyIOStream(py::object io, std::vector<uint8_t> data) :
  VectorStream(std::move(data)),
  io_{io}
{}


PyIOStream::~PyIOStream() = default;
}
