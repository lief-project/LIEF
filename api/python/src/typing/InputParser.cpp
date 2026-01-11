/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "LIEF/logging.hpp"

#include <nanobind/stl/vector.h>

#include "typing/InputParser.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "pyIOStream.hpp"
#include "pyutils.hpp"

namespace LIEF::py::typing {
std::unique_ptr<BinaryStream> InputParser::into_stream() {
  if (auto path_str = path_to_str(*this)) {
    if (auto strm = VectorStream::from_file(*path_str)) {
      return std::make_unique<VectorStream>(std::move(*strm));
    }
    return nullptr;
  }

  if (nb::isinstance<nb::bytes>(*this)) {
    auto bytes = nb::cast<nb::bytes>(*this);
    return std::make_unique<SpanStream>(
      static_cast<const uint8_t*>(bytes.data()), bytes.size()
    );
  }

  if (nb::isinstance<nb::list>(*this)) {
    auto bytes = nb::cast<std::vector<uint8_t>>(*this);
    return std::make_unique<VectorStream>(std::move(bytes));
  }

  if (auto stream = PyIOStream::from_python(*this)) {
    return std::make_unique<PyIOStream>(std::move(*stream));
  }

  logging::log(logging::LEVEL::ERR,
               "LIEF parser interface does not support this Python object: " +
               type2str(*this));
  return nullptr;
}
}
