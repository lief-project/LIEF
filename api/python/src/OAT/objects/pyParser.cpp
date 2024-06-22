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
#include "OAT/pyOAT.hpp"

#include "pyIOStream.hpp"
#include "pyutils.hpp"
#include "typing/InputParser.hpp"

#include "LIEF/OAT/Parser.hpp"
#include "LIEF/OAT/Binary.hpp"
#include "LIEF/logging.hpp"

#include <string>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::OAT::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse",
    nb::overload_cast<const std::string&>(&Parser::parse),
    "Parse the given OAT file and return a " RST_CLASS_REF(lief.OAT.Binary) " object"_doc,
    "oat_file"_a, nb::rv_policy::take_ownership);

  m.def("parse",
    nb::overload_cast<const std::string&, const std::string&>(&Parser::parse),
    "Parse the given OAT with its VDEX file and return a " RST_CLASS_REF(lief.OAT.Binary) " object"_doc,
    "oat_file"_a, "vdex_file"_a, nb::rv_policy::take_ownership);

  m.def("parse",
    nb::overload_cast<std::vector<uint8_t>>(&Parser::parse),
    "Parse the given raw data and return a " RST_CLASS_REF(lief.OAT.Binary) " object"_doc,
    "raw"_a, nb::rv_policy::take_ownership);

  m.def("parse",
    [] (typing::InputParser obj) -> std::unique_ptr<Binary> {
      if (auto path_str = path_to_str(obj)) {
        return Parser::parse(std::move(*path_str));
      }

      if (auto stream = PyIOStream::from_python(obj)) {
        auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
        return Parser::parse(stream->content());
      }
      logging::log(logging::LEVEL::ERR,
                   "LIEF parser interface does not support Python object: " +
                   type2str(obj));
      return nullptr;
    },
    "obj"_a,
    nb::rv_policy::take_ownership);
}
}
