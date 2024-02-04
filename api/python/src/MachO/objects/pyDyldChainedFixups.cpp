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

#include "pyIterator.hpp"
#include "LIEF/MachO/DyldChainedFixups.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/ChainedBindingInfo.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<DyldChainedFixups>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<DyldChainedFixups, LoadCommand> chained(m, "DyldChainedFixups",
      R"delim(
      Class that represents the LC_DYLD_CHAINED_FIXUPS command

      This command aims at providing rebase and binding information like
      the :class:`~lief.MachO.DyldInfo` 's bytecode. Compared to the :class:`~lief.MachO.DyldInfo` bytecode,
      these chained fixups are taking less space.
      )delim"_doc);

  init_ref_iterator<DyldChainedFixups::it_binding_info>(chained, "it_binding_info");
  init_ref_iterator<DyldChainedFixups::it_chained_starts_in_segments_t>(chained, "it_chained_starts_in_segments_t");

  nb::class_<DyldChainedFixups::chained_starts_in_segment>(chained, "chained_starts_in_segment",
      R"delim(
      Structure that mirrors the raw dyld_chained_starts_in_segment
      which aims at providing information about the chained rebase/bind fixups

      The relocations provided by this structure can be accessed through :attr:`~lief.MachO.SegmentCommand.relocations`
      )delim"_doc)
    .def_ro("offset", &DyldChainedFixups::chained_starts_in_segment::offset,
            "Original offset of the structure, relative to :attr:`~lief.MachO.DyldChainedFixups.starts_offset`"_doc)
    .def_ro("size", &DyldChainedFixups::chained_starts_in_segment::size,
            "``sizeof(size) + sizeof(page_size) + ... + sizeof(pointer_format)``"_doc)
    .def_ro("page_size", &DyldChainedFixups::chained_starts_in_segment::page_size,
            "Likely 0x1000 for x86/x86_64 architectures and 0x4000 for ARM64 architecture"_doc)
    .def_ro("segment_offset", &DyldChainedFixups::chained_starts_in_segment::segment_offset,
            R"delim(
            Offset of the segment's data from the beginning of the file.
            (it should match :attr:`~lief.MachO.SegmentCommand.file_offset`)
            )delim"_doc)
    .def_ro("page_start", &DyldChainedFixups::chained_starts_in_segment::page_start,
            R"delim(
            Offset in the :class:`~lief.MachO.SegmentCommand` of the first
            element of the chain.
            )delim"_doc)
    .def_ro("pointer_format", &DyldChainedFixups::chained_starts_in_segment::pointer_format,
            R"delim(How pointers are encoded)delim"_doc)
    .def_ro("max_valid_pointer", &DyldChainedFixups::chained_starts_in_segment::max_valid_pointer,
            R"delim(for 32-bit OS, any value beyond this is not a pointer)delim"_doc)
    .def_prop_ro("page_count",
        &DyldChainedFixups::chained_starts_in_segment::page_count,
        "How many pages are in the :attr:`~lief.MachO.DyldChainedFixups.page_start` array"_doc)

    .def_prop_ro("segment",
        [] (DyldChainedFixups::chained_starts_in_segment& self) -> SegmentCommand* {
          return &self.segment;
        },
        ":class:`~lief.MachO.SegmentCommand` in which the rebase/bind fixups take place"_doc,
        nb::rv_policy::reference_internal)

      LIEF_DEFAULT_STR(DyldChainedFixups::chained_starts_in_segment);

  chained
    .def_prop_rw("data_offset",
        nb::overload_cast<>(&DyldChainedFixups::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::data_offset),
        R"delim(
        Offset of the LC_DYLD_CHAINED_FIXUPS chained payload.
        This offset should point in the ``__LINKEDIT`` segment
        )delim"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&DyldChainedFixups::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::data_size),
        "Size of the LC_DYLD_CHAINED_FIXUPS payload"_doc)

    .def_prop_ro("bindings",
        nb::overload_cast<>(&DyldChainedFixups::bindings),
        "Iterator over the bindings " RST_CLASS_REF(lief.MachO.ChainedBindingInfo)
        " associated with this command"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("chained_starts_in_segments",
        nb::overload_cast<>(&DyldChainedFixups::chained_starts_in_segments),
        "Iterator over the chained fixup metadata, " RST_CLASS_REF(lief.MachO.DyldChainedFixups.chained_starts_in_segment) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_rw("fixups_version",
        nb::overload_cast<>(&DyldChainedFixups::fixups_version, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::fixups_version),
        R"delim(
        Chained fixups version. The loader (as far of dyld v852.2) checks
        that this value is set to 0.
        )delim"_doc)

    .def_prop_rw("starts_offset",
        nb::overload_cast<>(&DyldChainedFixups::starts_offset, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::starts_offset),
        R"delim(offset of dyld_chained_starts_in_image in chain_data)delim"_doc)

    .def_prop_rw("imports_offset",
        nb::overload_cast<>(&DyldChainedFixups::imports_offset, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::imports_offset),
        R"delim(Offset of imports table in chain data)delim"_doc)

    .def_prop_rw("symbols_offset",
        nb::overload_cast<>(&DyldChainedFixups::symbols_offset, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::symbols_offset),
        R"delim(Offset of symbol strings in chain data)delim"_doc)

    .def_prop_rw("imports_count",
        nb::overload_cast<>(&DyldChainedFixups::imports_count, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::imports_count),
        R"delim(Number of imported symbol names)delim"_doc)

    .def_prop_rw("symbols_format",
        nb::overload_cast<>(&DyldChainedFixups::symbols_format, nb::const_),
        nb::overload_cast<uint32_t>(&DyldChainedFixups::symbols_format),
        R"delim(
        The compression algorithm (if any) used to store the symbols
        0 means uncompressed while 1 means zlib compressed.

        As far of the version v852.2 of dyld loader, it only supports
        **uncompressed** format
        )delim"_doc)

    .def_prop_rw("imports_format",
        nb::overload_cast<>(&DyldChainedFixups::imports_format, nb::const_),
        nb::overload_cast<DYLD_CHAINED_FORMAT>(&DyldChainedFixups::imports_format),
        R"delim(
        The format of the imports (:class:`~lief.MachO.ChainedBindingInfo`)
        )delim"_doc)

    LIEF_DEFAULT_STR(DyldChainedFixups);
}

}
