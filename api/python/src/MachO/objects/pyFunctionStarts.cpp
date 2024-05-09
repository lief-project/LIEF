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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "LIEF/MachO/FunctionStarts.hpp"

#include "MachO/pyMachO.hpp"
#include "nanobind/extra/memoryview.hpp"

namespace LIEF::MachO::py {

template<>
void create<FunctionStarts>(nb::module_& m) {
  nb::class_<FunctionStarts, LoadCommand>(m, "FunctionStarts",
      R"delim(
      Class which represents the LC_FUNCTION_STARTS command

      This command is an array of ULEB128 encoded values
      )delim"_doc)

    .def_prop_rw("data_offset",
        nb::overload_cast<>(&FunctionStarts::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&FunctionStarts::data_offset),
        "Offset in the binary where *start functions* are located"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&FunctionStarts::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&FunctionStarts::data_size),
        "Size of the functions list in the binary"_doc)

    .def_prop_rw("functions",
        nb::overload_cast<>(&FunctionStarts::functions, nb::const_),
        nb::overload_cast<std::vector<uint64_t>>(&FunctionStarts::functions),
        R"delim(
        Addresses of every function entry point in the executable

        This allows functions to exist for which there are no entries in the symbol table.

        .. warning::

          The address is relative to the ``__TEXT`` segment
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def("add_function", &FunctionStarts::add_function,
      "Add a new function"_doc,
      "address"_a)

    .def_prop_ro("content",
        [] (const FunctionStarts& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream"_doc)

  LIEF_DEFAULT_STR(FunctionStarts);

}
}
