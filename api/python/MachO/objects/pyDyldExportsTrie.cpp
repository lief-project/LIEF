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

#include "pyIterators.hpp"

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<DyldExportsTrie>(py::module& m) {

  py::class_<DyldExportsTrie, LoadCommand> exports_trie(m, "DyldExportsTrie",
      R"delim(
      Class that represents the LC_DYLD_EXPORTS_TRIE command

      In recent Mach-O binaries, this command replace the DyldInfo export trie buffer
      )delim");

  try {
    init_ref_iterator<DyldExportsTrie::it_export_info>(exports_trie, "it_export_info");
  } catch (const std::runtime_error&) { }

  exports_trie
    .def_property("data_offset",
                  py::overload_cast<>(&DyldExportsTrie::data_offset, py::const_),
                  py::overload_cast<uint32_t>(&DyldExportsTrie::data_offset),
                  "Offset of the trie in the binary. This offset should point in the __LINKEDIT")

    .def_property("data_size",
                  py::overload_cast<>(&DyldExportsTrie::data_size, py::const_),
                  py::overload_cast<uint32_t>(&DyldExportsTrie::data_size),
                  "Raw size of the trie")

    .def_property_readonly("content",
        [] (const DyldExportsTrie& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The raw export trie")

    .def_property_readonly("exports",
                           py::overload_cast<>(&DyldExportsTrie::exports),
                           R"delim(
                           Iterator over the :class:`~lief.MachO.ExportInfo` associated with
                           this trie.
                           )delim")

    .def("show_export_trie",
         &DyldExportsTrie::show_export_trie,
         "Show the trie in a humman-readable way")

    .def("__eq__", &DyldExportsTrie::operator==)
    .def("__ne__", &DyldExportsTrie::operator!=)
    .def("__hash__",
        [] (const DyldExportsTrie& info) {
          return Hash::hash(info);
        })

    .def("__str__",
        [] (const DyldExportsTrie& info) {
          std::ostringstream stream;
          std::string str = stream.str();
          return stream.str();
        });

}

}
}
