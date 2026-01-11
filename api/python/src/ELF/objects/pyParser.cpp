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
#include "ELF/pyELF.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "typing/InputParser.hpp"

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"

#include "LIEF/BinaryStream/BinaryStream.hpp"

namespace LIEF::ELF::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse",
      [] (typing::InputParser obj, const ParserConfig& config) -> std::unique_ptr<Binary> {
        return Parser::parse(obj.into_stream(), config);
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
