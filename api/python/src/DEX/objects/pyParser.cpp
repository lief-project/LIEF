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
#include "DEX/pyDEX.hpp"

#include "LIEF/DEX/Parser.hpp"
#include "LIEF/DEX/File.hpp"
#include "LIEF/logging.hpp"

#include "pyutils.hpp"
#include "pyIOStream.hpp"
#include "typing/InputParser.hpp"

#include <string>
#include <memory>

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::DEX::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse",
    static_cast<std::unique_ptr<File> (*) (const std::string&)>(&Parser::parse),
    "Parse the given filename and return a " RST_CLASS_REF(lief.DEX.File) " object"_doc,
    "filename"_a,
    nb::rv_policy::take_ownership);

  m.def("parse",
    static_cast<std::unique_ptr<File>(*)(std::vector<uint8_t>, const std::string&)>(&Parser::parse),
    "Parse the given raw data and return a " RST_CLASS_REF(lief.DEX.File) " object"_doc,
    "raw"_a, "name"_a = "",
    nb::rv_policy::take_ownership);

  m.def("parse",
    [] (typing::InputParser obj, const std::string& name) -> std::unique_ptr<File> {
      if (auto path_str = path_to_str(obj)) {
        return DEX::Parser::parse(std::move(*path_str));
      }

      if (auto stream = PyIOStream::from_python(obj)) {
        auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
        return DEX::Parser::parse(stream->content(), name);
      }

      logging::log(logging::LEVEL::ERR,
                   "LIEF parser interface does not support Python object: " +
                   type2str(obj));
      return nullptr;
    }, "obj"_a, "name"_a = "",
    nb::rv_policy::take_ownership);
}
}
