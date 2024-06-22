
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
#include "PE/pyPE.hpp"

#include <string>
#include <memory>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "typing/InputParser.hpp"
#include "pyutils.hpp"
#include "pyIOStream.hpp"
#include "LIEF/logging.hpp"

#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Binary.hpp"

namespace LIEF::PE::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse",
    static_cast<std::unique_ptr<Binary>(*)(const std::string&, const ParserConfig&)>(&Parser::parse),
    "Parse the PE binary from the given **file path** and return a " RST_CLASS_REF(lief.PE.Binary) " object"_doc,
    "filename"_a, "config"_a = ParserConfig::all(),
    nb::rv_policy::take_ownership);

  m.def("parse",
      static_cast<std::unique_ptr<Binary>(*)(std::vector<uint8_t>, const ParserConfig&)>(&Parser::parse),
    "Parse the PE binary from the given **list of bytes** and return a :class:`lief.PE.Binary` object"_doc,
    "raw"_a, "config"_a = ParserConfig::all(),
    nb::rv_policy::take_ownership);

  m.def("parse",
    [] (typing::InputParser obj, const ParserConfig&) -> std::unique_ptr<Binary> {
      if (auto path_str = path_to_str(obj)) {
        return Parser::parse(std::move(*path_str));
      }
      if (auto stream = PyIOStream::from_python(obj)) {
        auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
        return PE::Parser::parse(std::move(ptr));
      }
      logging::log(logging::LEVEL::ERR,
                   "LIEF parser interface does not support Python object: " +
                   type2str(obj));
      return nullptr;
    },
    "Parse the PE binary from the given parameter and return a :class:`lief.PE.Binary` object"_doc,
    "obj"_a, "config"_a = ParserConfig::all(),
    nb::rv_policy::take_ownership);
}

}
