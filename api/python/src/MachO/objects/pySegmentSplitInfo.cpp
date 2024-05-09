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

#include "LIEF/MachO/SegmentSplitInfo.hpp"

#include "MachO/pyMachO.hpp"
#include "nanobind/extra/memoryview.hpp"

namespace LIEF::MachO::py {

template<>
void create<SegmentSplitInfo>(nb::module_& m) {

  nb::class_<SegmentSplitInfo, LoadCommand>(m, "SegmentSplitInfo",
      "Class that represents the :attr:`~.LoadCommand.TYPE.SEGMENT_SPLIT_INFO` command"_doc)

    .def_prop_rw("data_offset",
        nb::overload_cast<>(&SegmentSplitInfo::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&SegmentSplitInfo::data_offset),
        "Offset in the binary where the data start"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&SegmentSplitInfo::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&SegmentSplitInfo::data_size),
        "Size of the raw data"_doc)

    .def_prop_ro("content",
        [] (const SegmentSplitInfo& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream"_doc)

    LIEF_DEFAULT_STR(SegmentSplitInfo);

}
}
