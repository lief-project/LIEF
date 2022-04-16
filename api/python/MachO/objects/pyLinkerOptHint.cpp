/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/LinkerOptHint.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<LinkerOptHint>(py::module& m) {

  py::class_<LinkerOptHint, LoadCommand>(m, "LinkerOptHint",
    R"delim(
    Class which represents the `LC_LINKER_OPTIMIZATION_HINT` command
    )delim")

    .def_property("data_offset",
        py::overload_cast<>(&LinkerOptHint::data_offset, py::const_),
        py::overload_cast<uint32_t>(&LinkerOptHint::data_offset),
        "Offset in the binary where the payload starts")

    .def_property("data_size",
        py::overload_cast<>(&LinkerOptHint::data_offset, py::const_),
        py::overload_cast<uint32_t>(&LinkerOptHint::data_offset),
        "Size of the raw payload")

    .def_property_readonly("content",
        [] (const LinkerOptHint& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The raw payload")

    .def("__eq__", &LinkerOptHint::operator==)
    .def("__ne__", &LinkerOptHint::operator!=)
    .def("__hash__",
        [] (const LinkerOptHint& opt) {
          return Hash::hash(opt);
        })

    .def("__str__",
        [] (const LinkerOptHint& opt)
        {
          std::ostringstream stream;
          stream << opt;
          return stream.str();
        });

}

}
}
