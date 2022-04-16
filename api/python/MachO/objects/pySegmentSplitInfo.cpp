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
#include "LIEF/MachO/SegmentSplitInfo.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (SegmentSplitInfo::*)(void) const;

template<class T>
using setter_t = void (SegmentSplitInfo::*)(T);


template<>
void create<SegmentSplitInfo>(py::module& m) {

  py::class_<SegmentSplitInfo, LoadCommand>(m, "SegmentSplitInfo",
      "Class that represents the LOAD_COMMAND_TYPES::LC_SEGMENT_SPLIT_INFO command")

    .def_property("data_offset",
        static_cast<getter_t<uint32_t>>(&SegmentSplitInfo::data_offset),
        static_cast<setter_t<uint32_t>>(&SegmentSplitInfo::data_offset),
        "Offset in the binary where the data start")

    .def_property("data_size",
        static_cast<getter_t<uint32_t>>(&SegmentSplitInfo::data_size),
        static_cast<setter_t<uint32_t>>(&SegmentSplitInfo::data_size),
        "Size of the raw data")

    .def_property_readonly("content",
        [] (const SegmentSplitInfo& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream")

    .def("__eq__", &SegmentSplitInfo::operator==)
    .def("__ne__", &SegmentSplitInfo::operator!=)
    .def("__hash__",
        [] (const SegmentSplitInfo& func) {
          return Hash::hash(func);
        })


    .def("__str__",
        [] (const SegmentSplitInfo& func)
        {
          std::ostringstream stream;
          stream << func;
          std::string str = stream.str();
          return str;
        });
}

}
}
