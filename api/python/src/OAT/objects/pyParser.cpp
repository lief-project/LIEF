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
#include "OAT/pyOAT.hpp"

#include "pyIOStream.hpp"

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
    [] (nb::object byteio) -> nb::object {
      if (auto stream = PyIOStream::from_python(std::move(byteio))) {
        auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
        return nb::cast(Parser::parse(stream->content()));
      }
      logging::log(logging::LOG_ERR, "Can't create a LIEF stream interface over the provided io");
      return nb::none();
    }, "io"_a, nb::rv_policy::take_ownership);
}
}
