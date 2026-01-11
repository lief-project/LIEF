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
#include <memory>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "typing/InputParser.hpp"

#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/FatBinary.hpp"

#include "LIEF/BinaryStream/BinaryStream.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;


  m.def("parse_from_memory",
    nb::overload_cast<uintptr_t, const ParserConfig&>(&MachO::Parser::parse_from_memory),
    R"delim(
    Parse the Mach-O binary from the address given in the first parameter
    )delim"_doc, "address"_a, "config"_a = ParserConfig::deep(),
    nb::rv_policy::take_ownership);

  m.def("parse",
    [] (typing::InputParser obj, const ParserConfig& config) -> std::unique_ptr<FatBinary> {
      return Parser::parse(obj.into_stream(), config);
    },
    R"delim(
    Parse the given binary from the given input and return a :class:`~lief.MachO.FatBinary` object

    One can configure the parser with the ``config`` parameter. See :class:`~lief.MachO.ParserConfig`
    )delim"_doc,
    "obj"_a, "config"_a = ParserConfig::deep(),
    nb::rv_policy::take_ownership);
}

}
