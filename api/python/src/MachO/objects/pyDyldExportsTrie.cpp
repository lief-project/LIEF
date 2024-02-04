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

#include "pyIterator.hpp"
#include "nanobind/extra/memoryview.hpp"

#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<DyldExportsTrie>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<DyldExportsTrie, LoadCommand> exports_trie(m, "DyldExportsTrie",
      R"delim(
      Class that represents the LC_DYLD_EXPORTS_TRIE command

      In recent Mach-O binaries, this command replace the DyldInfo export trie buffer
      )delim"_doc);

  try {
    init_ref_iterator<DyldExportsTrie::it_export_info>(exports_trie, "it_export_info");
  } catch (const std::runtime_error&) { }

  exports_trie
    .def_prop_rw("data_offset",
                 nb::overload_cast<>(&DyldExportsTrie::data_offset, nb::const_),
                 nb::overload_cast<uint32_t>(&DyldExportsTrie::data_offset),
                 "Offset of the trie in the binary. This offset should point in the __LINKEDIT"_doc)

    .def_prop_rw("data_size",
                 nb::overload_cast<>(&DyldExportsTrie::data_size, nb::const_),
                 nb::overload_cast<uint32_t>(&DyldExportsTrie::data_size),
                 "Raw size of the trie"_doc)

    .def_prop_ro("content",
        [] (const DyldExportsTrie& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        }, "The raw export trie"_doc)

    .def_prop_ro("exports",
                 nb::overload_cast<>(&DyldExportsTrie::exports),
                 R"delim(
                 Iterator over the :class:`~lief.MachO.ExportInfo` associated with
                 this trie.
                 )delim"_doc)

    .def("show_export_trie",
         &DyldExportsTrie::show_export_trie,
         "Show the trie in a humman-readable way"_doc)

    LIEF_DEFAULT_STR(DyldExportsTrie);
}

}
