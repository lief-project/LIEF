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
#include "Section.hpp"

namespace LIEF {
namespace PE {
void init_c_sections(Pe_Binary_t* c_binary, Binary* binary) {

  Binary::it_sections sections = binary->sections();

  c_binary->sections = static_cast<Pe_Section_t**>(
      malloc((sections.size() + 1) * sizeof(Pe_Section_t**)));

  for (size_t i = 0; i < sections.size(); ++i) {
    Section& b_section = sections[i];
    c_binary->sections[i] = static_cast<Pe_Section_t*>(malloc(sizeof(Pe_Section_t)));
    span<const uint8_t> section_content = b_section.content();
    uint8_t* content = nullptr;

    if (!section_content.empty()) {
      content = static_cast<uint8_t*>(malloc(section_content.size() * sizeof(uint8_t)));
      std::copy(std::begin(section_content), std::end(section_content),
                content);
    }

    c_binary->sections[i]->name                    = b_section.fullname().c_str();
    c_binary->sections[i]->virtual_address         = b_section.virtual_address();
    c_binary->sections[i]->size                    = b_section.size();
    c_binary->sections[i]->offset                  = b_section.offset();
    c_binary->sections[i]->virtual_size            = b_section.virtual_size();
    c_binary->sections[i]->pointerto_relocation    = b_section.pointerto_relocation();
    c_binary->sections[i]->pointerto_line_numbers  = b_section.pointerto_line_numbers();
    c_binary->sections[i]->characteristics         = b_section.characteristics();
    c_binary->sections[i]->content                 = content;
    c_binary->sections[i]->content_size            = section_content.size();
    c_binary->sections[i]->entropy                 = b_section.entropy();
  }
  c_binary->sections[sections.size()] = nullptr;

}



void destroy_sections(Pe_Binary_t* c_binary) {

  Pe_Section_t **sections = c_binary->sections;
  for (size_t idx = 0; sections[idx] != nullptr; ++idx) {
    free(sections[idx]->content);
    free(sections[idx]);
  }
  free(c_binary->sections);

}

}
}


