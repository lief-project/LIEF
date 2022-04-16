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
#include "LIEF/MachO/CodeSignature.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (CodeSignature::*)(void) const;

template<class T>
using setter_t = void (CodeSignature::*)(T);


template<>
void create<CodeSignature>(py::module& m) {

  py::class_<CodeSignature, LoadCommand>(m, "CodeSignature")

    .def_property("data_offset",
        static_cast<getter_t<uint32_t>>(&CodeSignature::data_offset),
        static_cast<setter_t<uint32_t>>(&CodeSignature::data_offset),
        "Offset in the binary where the signature starts")

    .def_property("data_size",
        static_cast<getter_t<uint32_t>>(&CodeSignature::data_size),
        static_cast<setter_t<uint32_t>>(&CodeSignature::data_size),
        "Size of the raw signature")

    .def_property_readonly("content",
        [] (const CodeSignature& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The raw signature as a bytes stream")

    .def("__eq__", &CodeSignature::operator==)
    .def("__ne__", &CodeSignature::operator!=)
    .def("__hash__",
        [] (const CodeSignature& func) {
          return Hash::hash(func);
        })

    .def("__str__",
        [] (const CodeSignature& func)
        {
          std::ostringstream stream;
          stream << func;
          std::string str = stream.str();
          return str;
        });

}

}
}
