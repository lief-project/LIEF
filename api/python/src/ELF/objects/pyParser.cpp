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
#include "pyELF.hpp"

#include "PyIOStream.hpp"
#include "LIEF/logging.hpp"

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"

#include <string>

namespace LIEF {
namespace ELF {

template<>
void create<Parser>(py::module& m) {

  // Parser (Parser)
  m.def("parse",
    static_cast<std::unique_ptr<Binary> (*) (const std::string&, DYNSYM_COUNT_METHODS)>(&Parser::parse),
    R"delim(
    Parse the ELF binary from the given **file path** and return a :class:`lief.ELF.Binary` object

    For *weird* binaries (e.g sectionless) you can choose the method to use to count dynamic symbols
    (:class:`lief.ELF.DYNSYM_COUNT_METHODS`). By default, the value is set to
    :attr:`lief.ELF.DYNSYM_COUNT_METHODS.COUNT_AUTO`
    )delim",
    "filename"_a, "dynsym_count_method"_a = DYNSYM_COUNT_METHODS::COUNT_AUTO,
    py::return_value_policy::take_ownership);

  m.def("parse",
    static_cast<std::unique_ptr<Binary>(*)(const std::vector<uint8_t>&, DYNSYM_COUNT_METHODS)>(&Parser::parse),
    R"delim(
    Parse the ELF binary from the given **list of bytes** and return a :class:`lief.ELF.Binary` object

    For *weird* binaries (e.g sectionless) you can choose the method to use to count dynamic symbols
    (:class:`lief.ELF.DYNSYM_COUNT_METHODS`). By default, the value is set to
    :attr:`lief.ELF.DYNSYM_COUNT_METHODS.COUNT_AUTO`
    )delim",

    "raw"_a, "dynsym_count_method"_a = DYNSYM_COUNT_METHODS::COUNT_AUTO,
    py::return_value_policy::take_ownership);


  m.def("parse",
      [] (py::object byteio, DYNSYM_COUNT_METHODS count) -> py::object {
        if (auto stream = PyIOStream::from_python(byteio)) {
          auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
          return py::cast(ELF::Parser::parse(std::move(ptr), count));
        }
        logging::log(logging::LOG_ERR, "Can't create a LIEF stream interface over the provided io");
        return py::none();
      },
      R"delim(
      Parse the ELF binary from a Python IO stream and return a :class:`lief.ELF.Binary` object

      For *weird* binaries (e.g sectionless) you can choose the method to use to count dynamic symbols
      (:class:`lief.ELF.lief.ELF.DYNSYM_COUNT_METHODS`). By default, the value is set to
      :attr:`lief.ELF.lief.ELF.DYNSYM_COUNT_METHODS.COUNT_AUTO`
      )delim",
      "io"_a, "dynsym_count_method"_a = DYNSYM_COUNT_METHODS::COUNT_AUTO,
      py::return_value_policy::take_ownership);
}
}
}
