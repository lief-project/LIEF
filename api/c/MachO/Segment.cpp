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
#include "Segment.hpp"

namespace LIEF {
namespace MachO {
void init_c_segments(Macho_Binary_t* c_binary, Binary* binary) {
  Binary::it_segments segments = binary->segments();

  c_binary->segments = static_cast<Macho_Segment_t**>(
      malloc((segments.size() + 1) * sizeof(Macho_Segment_t**)));

  for (size_t i = 0; i < segments.size(); ++i) {
    SegmentCommand& segment = segments[i];

    c_binary->segments[i] = static_cast<Macho_Segment_t*>(malloc(sizeof(Macho_Segment_t)));
    span<const uint8_t> segment_content = segment.content();
    auto* content = static_cast<uint8_t*>(malloc(segment_content.size() * sizeof(uint8_t)));
    std::copy(
        std::begin(segment_content),
        std::end(segment_content),
        content);

    c_binary->segments[i]->name              = segment.name().c_str();
    c_binary->segments[i]->virtual_address   = segment.virtual_address();
    c_binary->segments[i]->virtual_size      = segment.virtual_size();
    c_binary->segments[i]->file_size         = segment.file_size();
    c_binary->segments[i]->file_offset       = segment.file_offset();
    c_binary->segments[i]->max_protection    = segment.max_protection();
    c_binary->segments[i]->init_protection   = segment.init_protection();
    c_binary->segments[i]->numberof_sections = segment.numberof_sections();
    c_binary->segments[i]->flags             = segment.flags();
    c_binary->segments[i]->content           = content;
    c_binary->segments[i]->size              = segment_content.size();
    c_binary->segments[i]->sections          = nullptr; //TODO
  }

  c_binary->segments[segments.size()] = nullptr;

}



void destroy_segments(Macho_Binary_t* c_binary) {
  Macho_Segment_t **segments = c_binary->segments;
  for (size_t idx = 0; segments[idx] != nullptr; ++idx) {
    free(segments[idx]->content);
    free(segments[idx]);
  }
  free(c_binary->segments);

}

}
}


