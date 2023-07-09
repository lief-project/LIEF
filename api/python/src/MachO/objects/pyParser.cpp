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
#include <string>
#include <memory>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "pyIOStream.hpp"

#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/logging.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<Parser>(nb::module_& m) {
  using namespace LIEF::py;

  m.def("parse",
    nb::overload_cast<const std::string&, const ParserConfig&>(&LIEF::MachO::Parser::parse),
    R"delim(
    Parse the given binary and return a :class:`~lief.MachO.FatBinary` object

    One can configure the parsing with the ``config`` parameter. See :class:`~lief.MachO.ParserConfig`,
    )delim"_doc, "filename"_a, "config"_a = ParserConfig::deep(),
    nb::rv_policy::take_ownership);


  m.def("parse",
    nb::overload_cast<const std::vector<uint8_t>&, const ParserConfig&>(&LIEF::MachO::Parser::parse),
    R"delim(
    Parse the given binary (from raw bytes) and return a :class:`~lief.MachO.FatBinary` object

    One can configure the parsing with the ``config`` parameter. See :class:`~lief.MachO.ParserConfig`
    )delim"_doc, "raw"_a, "config"_a = ParserConfig::quick(),
    nb::rv_policy::take_ownership);

  m.def("parse_from_memory",
    nb::overload_cast<uintptr_t, const ParserConfig&>(&MachO::Parser::parse_from_memory),
    R"delim(
    Parse the Mach-O binary from the address given in the first parameter
    )delim"_doc, "address"_a, "config"_a = ParserConfig::deep(),
    nb::rv_policy::take_ownership);

  m.def("parse",
    [] (nb::object byteio, const ParserConfig& config) -> nb::object {
      if (auto stream = PyIOStream::from_python(std::move(byteio))) {
        auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
        return nb::cast(MachO::Parser::parse(std::move(ptr), config));
      }
      logging::log(logging::LOG_ERR, "Can't create a LIEF stream interface over the provided io");
      return nb::none();
    },
    R"delim(
    Parse the given binary from a Python IO interface and return a :class:`~lief.MachO.FatBinary` object

    One can configure the parsing with the ``config`` parameter. See :class:`~lief.MachO.ParserConfig`
    )delim"_doc, "io"_a, "config"_a = ParserConfig::quick(),
    nb::rv_policy::take_ownership);
}

}
