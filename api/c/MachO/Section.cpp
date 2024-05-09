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
#include "Section.hpp"

namespace LIEF {
namespace MachO {
void init_c_sections(Macho_Binary_t* c_binary, Binary* binary) {
  Binary::it_sections sections = binary->sections();

  c_binary->sections = static_cast<Macho_Section_t**>(
      malloc((sections.size() + 1) * sizeof(Macho_Section_t**)));

  for (size_t i = 0; i < sections.size(); ++i) {
    const Section& section = sections[i];

    c_binary->sections[i] = static_cast<Macho_Section_t*>(malloc(sizeof(Macho_Section_t)));
    span<const uint8_t> section_content = section.content();
    auto* content = static_cast<uint8_t*>(malloc(section_content.size() * sizeof(uint8_t)));
    std::copy(std::begin(section_content), std::end(section_content),
              content);

    c_binary->sections[i]->name                 = section.fullname().c_str();
    c_binary->sections[i]->alignment            = section.alignment();
    c_binary->sections[i]->relocation_offset    = section.relocation_offset();
    c_binary->sections[i]->numberof_relocations = section.numberof_relocations();
    c_binary->sections[i]->flags                = section.raw_flags();
    c_binary->sections[i]->type                 = static_cast<enum LIEF_MACHO_MACHO_SECTION_TYPES>(section.type());
    c_binary->sections[i]->reserved1            = section.reserved1();
    c_binary->sections[i]->reserved2            = section.reserved2();
    c_binary->sections[i]->reserved3            = section.reserved3();
    c_binary->sections[i]->virtual_address      = section.virtual_address();
    c_binary->sections[i]->offset               = section.offset();
    c_binary->sections[i]->size                 = section_content.size();
    c_binary->sections[i]->content              = content;
    c_binary->sections[i]->entropy              = section.entropy();
  }

  c_binary->sections[sections.size()] = nullptr;

}


void destroy_sections(Macho_Binary_t* c_binary) {
  Macho_Section_t **sections = c_binary->sections;
  for (size_t idx = 0; sections[idx] != nullptr; ++idx) {
    free(sections[idx]->content);
    free(sections[idx]);
  }
  free(c_binary->sections);

}

}
}

