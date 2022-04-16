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
#include "LIEF/MachO/TwoLevelHints.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<TwoLevelHints>(py::module& m) {

  py::class_<TwoLevelHints, LoadCommand> cmd(m, "TwoLevelHints",
    R"delim(
    Class which represents the `LC_TWOLEVEL_HINTS` command
    )delim");

  cmd
    .def_property_readonly("hints",
        py::overload_cast<>(&TwoLevelHints::hints))
    .def_property_readonly("content",
        [] (const TwoLevelHints& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream")

    .def("__eq__", &TwoLevelHints::operator==)
    .def("__ne__", &TwoLevelHints::operator!=)
    .def("__hash__",
        [] (const TwoLevelHints& two) {
          return Hash::hash(two);
        })

    .def("__str__",
        [] (const TwoLevelHints& two) {
          std::ostringstream stream;
          stream << two;
          return stream.str();
        });

}

}
}
