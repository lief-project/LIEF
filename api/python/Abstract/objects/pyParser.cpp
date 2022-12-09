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
#include "pyAbstract.hpp"

#include "PyIOStream.hpp"
#include "logging.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include <string>
#include <stdexcept>

namespace LIEF {
template<>
void create<Parser>(py::module& m) {

  m.def("parse",
      [] (py::bytes bytes, const std::string& name) {
        std::string raw_str = bytes;
        std::vector<uint8_t> raw = {
          std::make_move_iterator(std::begin(raw_str)),
          std::make_move_iterator(std::end(raw_str))
        };
        std::unique_ptr<Binary> binary;
        std::exception_ptr ep;
        Py_BEGIN_ALLOW_THREADS
        try {
          binary = Parser::parse(std::move(raw), name);
        } catch (...) {
          ep = std::current_exception();
        }
        Py_END_ALLOW_THREADS
        if (ep) std::rethrow_exception(ep);
        return binary;
      },
      R"delim(
      Parse a binary supported by LIEF from the given bytes and return either:

      - :class:`lief.ELF.Binary`
      - :class:`lief.PE.Binary`
      - :class:`lief.MachO.Binary`

      depending on the given binary format.
      )delim",
      "raw"_a, "name"_a = "",
      py::return_value_policy::take_ownership);

  m.def("parse",
      [] (const std::string& filepath) {
        std::unique_ptr<Binary> binary;
        std::exception_ptr ep;
        Py_BEGIN_ALLOW_THREADS
        try {
          binary = Parser::parse(filepath);
        } catch (...) {
          ep = std::current_exception();
        }
        Py_END_ALLOW_THREADS
        if (ep) std::rethrow_exception(ep);
        return binary;
      },
      R"delim(
      Parse a binary from the given file path and return either:

      - :class:`lief.ELF.Binary`
      - :class:`lief.PE.Binary`
      - :class:`lief.MachO.Binary`

      depending on the given binary format.
      )delim",
      "filepath"_a,
      py::return_value_policy::take_ownership);


  m.def("parse",
      [] (py::object byteio, const std::string& name) -> py::object {
        if (auto stream = PyIOStream::from_python(byteio)) {
          auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
          py::object binary;
          std::exception_ptr ep;
          Py_BEGIN_ALLOW_THREADS
          try {
            binary = py::cast(Parser::parse(std::move(ptr)));
          } catch (...) {
            ep = std::current_exception();
          }
          Py_END_ALLOW_THREADS
          if (ep) std::rethrow_exception(ep);
          return binary;
        }
        LIEF_ERR("Can't create a LIEF stream interface over the provided io");
        return py::none();
      },
      R"delim(
      Parse a binary supported by LIEF from the given Python IO interface and return either:

      - :class:`lief.ELF.Binary`
      - :class:`lief.PE.Binary`
      - :class:`lief.MachO.Binary`

      depending on the given binary format.
      )delim",
      "io"_a, "name"_a = "",
      py::return_value_policy::take_ownership);
}
}
