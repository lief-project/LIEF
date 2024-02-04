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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/CodeSignatureDir.hpp"

#include "MachO/pyMachO.hpp"
#include "nanobind/extra/memoryview.hpp"

namespace LIEF::MachO::py {

template<>
void create<CodeSignatureDir>(nb::module_& m) {

  nb::class_<CodeSignatureDir, LoadCommand>(m, "CodeSignatureDir")
    .def_prop_rw("data_offset",
        nb::overload_cast<>(&CodeSignatureDir::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&CodeSignatureDir::data_offset),
        "Offset in the binary where the signature starts"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&CodeSignatureDir::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&CodeSignatureDir::data_offset),
        "Size of the raw signature"_doc)

    .def_prop_ro("content",
        [] (const CodeSignatureDir& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        }, "The raw signature as a bytes stream"_doc)

  LIEF_DEFAULT_STR(CodeSignatureDir);
}
}
