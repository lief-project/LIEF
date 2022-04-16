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
#include "LIEF/MachO/DyldChainedFixups.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<DyldChainedFixups>(py::module& m) {

  py::class_<DyldChainedFixups, LoadCommand> chained(m, "DyldChainedFixups",
      R"delim(
      Class that represents the LC_DYLD_CHAINED_FIXUPS command

      This command aims at providing rebase and binding information like
      the :class:`~lief.MachO.DyldInfo` 's bytecode. Compared to the :class:`~lief.MachO.DyldInfo` bytecode,
      these chained fixups are taking less space.
      )delim");

  init_ref_iterator<DyldChainedFixups::it_binding_info>(chained, "it_binding_info");
  init_ref_iterator<DyldChainedFixups::it_chained_starts_in_segments_t>(chained, "it_chained_starts_in_segments_t");

  py::class_<DyldChainedFixups::chained_starts_in_segment>(chained, "chained_starts_in_segment",
      R"delim(
      Structure that mirrors the raw dyld_chained_starts_in_segment
      which aims at providing information about the chained rebase/bind fixups

      The relocations provided by this structure can be accessed through :attr:`~lief.MachO.SegmentCommand.relocations`
      )delim")
    .def_readonly("offset", &DyldChainedFixups::chained_starts_in_segment::offset,
                  "Original offset of the structure, relative to :attr:`~lief.MachO.DyldChainedFixups.starts_offset`")
    .def_readonly("size", &DyldChainedFixups::chained_starts_in_segment::size,
                  "``sizeof(size) + sizeof(page_size) + ... + sizeof(pointer_format)``")
    .def_readonly("page_size", &DyldChainedFixups::chained_starts_in_segment::page_size,
                  "Likely 0x1000 for x86/x86_64 architectures and 0x4000 for ARM64 architecture")
    .def_readonly("segment_offset", &DyldChainedFixups::chained_starts_in_segment::segment_offset,
                  R"delim(
                  Offset of the segment's data from the beginning of the file.
                  (it should match :attr:`~lief.MachO.SegmentCommand.file_offset`)
                  )delim")
    .def_readonly("page_start", &DyldChainedFixups::chained_starts_in_segment::page_start,
                  R"delim(
                  Offset in the :class:`~lief.MachO.SegmentCommand` of
                  the first element of the chain.
                  )delim")
    .def_readonly("pointer_format", &DyldChainedFixups::chained_starts_in_segment::pointer_format,
                  R"delim(
                  How pointers are encoded
                  )delim")
    .def_readonly("max_valid_pointer", &DyldChainedFixups::chained_starts_in_segment::max_valid_pointer,
                  R"delim(
                  for 32-bit OS, any value beyond this is not a pointer
                  )delim")
    .def_property_readonly("page_count",
        &DyldChainedFixups::chained_starts_in_segment::page_count,
        "How many pages are in the :attr:`~lief.MachO.DyldChainedFixups.page_start` array")

    .def_property_readonly("segment",
        [] (DyldChainedFixups::chained_starts_in_segment& self) -> SegmentCommand* {
          return &self.segment;
        },
        ":class:`~lief.MachO.SegmentCommand` in which the rebase/bind fixups take place",
        py::return_value_policy::reference)

    .def("__str__",
        [] (const DyldChainedFixups::chained_starts_in_segment& self) {
          std::ostringstream stream;
          stream << self;
          return stream.str();
        });

  chained
    .def_property("data_offset",
        py::overload_cast<>(&DyldChainedFixups::data_offset, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::data_offset),
        R"delim(
        Offset of the LC_DYLD_CHAINED_FIXUPS chained payload.
        This offset should point in the ``__LINKEDIT`` segment
        )delim")

    .def_property("data_size",
        py::overload_cast<>(&DyldChainedFixups::data_size, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::data_size),
        "Size of the LC_DYLD_CHAINED_FIXUPS payload")

    .def_property_readonly("bindings",
        py::overload_cast<>(&DyldChainedFixups::bindings),
        "Iterator over the bindings " RST_CLASS_REF(lief.MachO.ChainedBindingInfo)
        " associated with this command")

    .def_property_readonly("chained_starts_in_segments",
        py::overload_cast<>(&DyldChainedFixups::chained_starts_in_segments),
        "Iterator over the chained fixup metadata: " RST_CLASS_REF(lief.MachO.DyldChainedFixups.chained_starts_in_segment) "")

    .def_property("fixups_version",
        py::overload_cast<>(&DyldChainedFixups::fixups_version, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::fixups_version),
        R"delim(
        Chained fixups version. The loader (as far of dyld v852.2) checks that this value is set to 0.
        )delim")

    .def_property("starts_offset",
        py::overload_cast<>(&DyldChainedFixups::starts_offset, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::starts_offset),
        R"delim(
        offset of dyld_chained_starts_in_image in chain_data
        )delim")

    .def_property("imports_offset",
        py::overload_cast<>(&DyldChainedFixups::imports_offset, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::imports_offset),
        R"delim(
        Offset of imports table in chain data
        )delim")

    .def_property("symbols_offset",
        py::overload_cast<>(&DyldChainedFixups::symbols_offset, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::symbols_offset),
        R"delim(
        Offset of symbol strings in chain data
        )delim")

    .def_property("imports_count",
        py::overload_cast<>(&DyldChainedFixups::imports_count, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::imports_count),
        R"delim(
        Number of imported symbol names
        )delim")

    .def_property("symbols_format",
        py::overload_cast<>(&DyldChainedFixups::symbols_format, py::const_),
        py::overload_cast<uint32_t>(&DyldChainedFixups::symbols_format),
        R"delim(
        The compression algorithm (if any) used to store the symbols
        0 means uncompressed while 1 means zlib compressed.

        As far of the version v852.2 of dyld loader, it only supports
        **uncompressed** format
        )delim")

    .def_property("imports_format",
        py::overload_cast<>(&DyldChainedFixups::imports_format, py::const_),
        py::overload_cast<DYLD_CHAINED_FORMAT>(&DyldChainedFixups::imports_format),
        R"delim(
        The format of the imports (:class:`~lief.MachO.ChainedBindingInfo`)
        )delim")

    .def("__eq__", &DyldChainedFixups::operator==)
    .def("__ne__", &DyldChainedFixups::operator!=)
    .def("__hash__",
        [] (const DyldChainedFixups& func) {
          return Hash::hash(func);
        })

    .def("__str__",
        [] (const DyldChainedFixups& fixups) {
          std::ostringstream stream;
          stream << fixups;
          return stream.str();
        });

}

}
}
