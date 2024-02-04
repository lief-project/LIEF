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
namespace ELF {
void init_c_sections(Elf_Binary_t* c_binary, Binary* binary) {

  Binary::it_sections sections = binary->sections();

  c_binary->sections = static_cast<Elf_Section_t**>(
      malloc((sections.size() + 1) * sizeof(Elf_Section_t**)));

  for (size_t i = 0; i < sections.size(); ++i) {
    Section& b_section = sections[i];
    c_binary->sections[i] = static_cast<Elf_Section_t*>(malloc(sizeof(Elf_Section_t)));
    span<const uint8_t> section_content = b_section.content();

    c_binary->sections[i]->name            = b_section.fullname().c_str();
    c_binary->sections[i]->flags           = b_section.flags();
    c_binary->sections[i]->type            = static_cast<uint32_t>(b_section.type());
    c_binary->sections[i]->virtual_address = b_section.virtual_address();
    c_binary->sections[i]->offset          = b_section.file_offset();
    c_binary->sections[i]->original_size   = b_section.original_size();
    c_binary->sections[i]->link            = b_section.link();
    c_binary->sections[i]->info            = b_section.information();
    c_binary->sections[i]->alignment       = b_section.alignment();
    c_binary->sections[i]->entry_size      = b_section.entry_size();
    c_binary->sections[i]->size            = section_content.size();
    c_binary->sections[i]->entropy         = b_section.entropy();
    c_binary->sections[i]->content         = !section_content.empty() ?
                                             const_cast<uint8_t*>(section_content.data()) : nullptr;
  }
  c_binary->sections[sections.size()] = nullptr;

}



void destroy_sections(Elf_Binary_t* c_binary) {

  Elf_Section_t **sections = c_binary->sections;
  for (size_t idx = 0; sections[idx] != nullptr; ++idx) {
    free(sections[idx]);
  }
  free(c_binary->sections);

}

}
}


