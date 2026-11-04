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
#include "PE/pyPE.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>
#include <memory>

#include "typing/InputParser.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Parser.hpp"

#include "LIEF/BinaryStream/BinaryStream.hpp" // IWYU pragma: keep

namespace LIEF::PE::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse_from_memory",
        nb::overload_cast<uintptr_t, const ParserConfig&>(
            &Parser::parse_from_memory
        ),
        "Parse the PE binary at the given memory address"_doc, "address"_a,
        "config"_a = ParserConfig::default_conf());

  m.def(
      "parse_from_memory",
      nb::overload_cast<uintptr_t, size_t, const ParserConfig&>(
          &Parser::parse_from_memory
      ),
      "Parse the PE binary at the given memory address and with the given size"_doc,
      "address"_a, "size"_a, "config"_a = ParserConfig::default_conf()
  );

  m.def(
      "parse_from_dump",
      [](typing::InputParser obj, uint64_t addr, const ParserConfig& config) {
        return Parser::parse_from_dump(obj.into_stream(), addr, config);
      },
      R"delim(
      Parse the PE binary from a memory dump given in the first parameter.

      A dump is a raw capture of the process' memory that was mapped starting at
      the virtual address given in the second parameter.
      )delim"_doc,
      "obj"_a, "addr"_a, "config"_a = ParserConfig::default_conf(),
      nb::rv_policy::take_ownership
  );

  m.def(
      "parse",
      [](typing::InputParser obj,
         const ParserConfig& config) -> std::unique_ptr<Binary> {
        return Parser::parse(obj.into_stream(), config);
      },
      "Parse the PE binary from the given parameter and return a :class:`lief.PE.Binary` object"_doc,
      "obj"_a, "config"_a = ParserConfig::default_conf(),
      nb::rv_policy::take_ownership
  );
}

}
