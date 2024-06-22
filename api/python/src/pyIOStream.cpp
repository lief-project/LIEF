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
#include "pyIOStream.hpp"
#include "nanobind/extra/memoryview.hpp"
#include "pyutils.hpp"
#include "LIEF/logging.hpp"

static constexpr int PY_SEEK_SET = 0;
static constexpr int PY_SEEK_END = 2;

namespace LIEF::py {
PyIOStream::PyIOStream(PyIOStream&& other) = default;
PyIOStream& PyIOStream::operator=(PyIOStream&& other) = default;

result<PyIOStream> PyIOStream::from_python(nb::object object) {
  const nb::module_ mod_io = nb::module_::import_("io");
  const nb::object IOBase = mod_io.attr("IOBase");

  if (!isinstance(object, IOBase)) {
    logging::log(logging::LEVEL::ERR,
        "The provided io object does not sub-class io.IOBase");
    return make_error_code(lief_errors::read_error);
  }

  if (!nb::hasattr(object, "read") && !nb::hasattr(object, "readinto")) {
    logging::log(logging::LEVEL::ERR,
        "The provided io object does not implement read() or readinto()");
    return make_error_code(lief_errors::read_error);
  }

  auto seek = object.attr("seek");
  seek(0, PY_SEEK_SET);
  seek(0, PY_SEEK_END);
  const auto size = nb::cast<size_t>(object.attr("tell")());
  std::vector<uint8_t> data;
  data.resize(size);

  seek(0, PY_SEEK_SET);
  if (nb::hasattr(object, "readinto")) {
    auto view = nb::memoryview::from_memory(data.data(), size);
    object.attr("readinto")(view);
  }
  else if (nb::hasattr(object, "read")) {
    auto content = nb::cast<nb::bytes>(object.attr("read")(size));
    std::string tmp(content.c_str(), content.size());
    std::move(std::begin(tmp), std::end(tmp), data.data());
  }

  return PyIOStream(std::move(object), std::move(data));
}

PyIOStream::PyIOStream(nb::object io, std::vector<uint8_t> data) :
  VectorStream(std::move(data)),
  io_{std::move(io)}
{}


PyIOStream::~PyIOStream() = default;
}
