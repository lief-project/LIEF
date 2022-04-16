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
#include "LIEF/MachO/CodeSignatureDir.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<CodeSignatureDir>(py::module& m) {

  py::class_<CodeSignatureDir, LoadCommand>(m, "CodeSignatureDir")

    .def_property("data_offset",
        py::overload_cast<>(&CodeSignatureDir::data_offset, py::const_),
        py::overload_cast<uint32_t>(&CodeSignatureDir::data_offset),
        "Offset in the binary where the signature starts")

    .def_property("data_size",
        py::overload_cast<>(&CodeSignatureDir::data_offset, py::const_),
        py::overload_cast<uint32_t>(&CodeSignatureDir::data_offset),
        "Size of the raw signature")

    .def_property_readonly("content",
        [] (const CodeSignatureDir& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The raw signature as a bytes stream")

    .def("__eq__", &CodeSignatureDir::operator==)
    .def("__ne__", &CodeSignatureDir::operator!=)
    .def("__hash__",
        [] (const CodeSignatureDir& sig) {
          return Hash::hash(sig);
        })

    .def("__str__",
        [] (const CodeSignatureDir& dir)
        {
          std::ostringstream stream;
          stream << dir;
          return stream.str();
        });

}

}
}
