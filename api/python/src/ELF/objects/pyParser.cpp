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
#include "ELF/pyELF.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "typing/InputParser.hpp"
#include "pyutils.hpp"
#include "pyIOStream.hpp"
#include "LIEF/logging.hpp"

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"

namespace LIEF::ELF::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse",
    nb::overload_cast<const std::string&, const ParserConfig&>(&Parser::parse),
    R"delim(
    Parse the ELF binary from the given **file path** and return a :class:`lief.ELF.Binary` object

    The second argument is an optional configuration (:class:`~lief.ELF.ParserConfig`)
    that can be used to define which part(s) of the ELF should be parsed or skipped.

    )delim"_doc, "filename"_a, "config"_a = ParserConfig::all(),
    nb::rv_policy::take_ownership);

  m.def("parse",
    nb::overload_cast<const std::vector<uint8_t>&, const ParserConfig&>(&Parser::parse),
    R"delim(
    Parse the ELF binary from the given **list of bytes** and return a :class:`lief.ELF.Binary` object

    The second argument is an optional configuration (:class:`~lief.ELF.ParserConfig`)
    that can be used to define which part(s) of the ELF should be parsed or skipped.
    )delim"_doc, "raw"_a, "config"_a = ParserConfig::all(),
    nb::rv_policy::take_ownership);


  m.def("parse",
      [] (typing::InputParser obj, const ParserConfig& config) -> std::unique_ptr<Binary> {
        if (auto path_str = path_to_str(obj)) {
          return ELF::Parser::parse(std::move(*path_str));
        }

        if (auto stream = PyIOStream::from_python(obj)) {
          auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
          return ELF::Parser::parse(std::move(ptr), config);
        }
        logging::log(logging::LEVEL::ERR,
                     "LIEF parser interface does not support Python object: " +
                     type2str(obj));
        return nullptr;
      },
      R"delim(
      Parse the ELF binary from the given Python object and return a :class:`lief.ELF.Binary` object

      The second argument is an optional configuration (:class:`~lief.ELF.ParserConfig`)
      that can be used to define which part(s) of the ELF should be parsed or skipped.
      )delim"_doc,
      "obj"_a, "config"_a = ParserConfig::all(),
      nb::rv_policy::take_ownership);
}
}
