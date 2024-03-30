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
#include <cstring>
#include "LIEF/ELF/Binary.h"
#include "LIEF/ELF/Section.h"
#include "LIEF/ELF/Segment.h"
#include "LIEF/ELF/Header.h"
#include "LIEF/ELF/Symbol.h"

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"

#include "Section.hpp"
#include "Segment.hpp"
#include "DynamicEntry.hpp"
#include "Symbol.hpp"
#include "Header.hpp"
#include "Binary.hpp"

using namespace LIEF::ELF;

namespace LIEF {
namespace ELF {
void init_c_binary(Elf_Binary_t* c_binary, Binary* binary) {
  c_binary->handler     = reinterpret_cast<void*>(binary);
  c_binary->type        = static_cast<uint32_t>(binary->type());
  c_binary->interpreter = nullptr;
  if (binary->has_interpreter()) {
    const std::string& interp = binary->interpreter();
    c_binary->interpreter = static_cast<char*>(malloc((interp.size() + 1) * sizeof(char)));
    std::memcpy(
        reinterpret_cast<void*>(const_cast<char*>(c_binary->interpreter)),
        reinterpret_cast<const void*>(interp.data()),
        interp.size());
    reinterpret_cast<char*>(const_cast<char*>(c_binary->interpreter))[interp.size()] = '\0';
  }

  init_c_header(c_binary, binary);
  init_c_sections(c_binary, binary);
  init_c_segments(c_binary, binary);
  init_c_dynamic_symbols(c_binary, binary);
  init_c_symtab_symbols(c_binary, binary);
  init_c_dynamic_entries(c_binary, binary);
}

}
}

Elf_Binary_t* elf_parse(const char *file) {
  Binary* binary = Parser::parse(file).release();

  if (binary == nullptr) {
    return nullptr;
  }

  auto* c_binary = static_cast<Elf_Binary_t*>(malloc(sizeof(Elf_Binary_t)));
  memset(c_binary, 0, sizeof(Elf_Binary_t));
  init_c_binary(c_binary, binary);
  return c_binary;
}

// Binary Methods
// ==============

int elf_binary_save_header(Elf_Binary_t* binary) {
  Header& hdr = reinterpret_cast<Binary*>(binary->handler)->header();

  hdr.file_type(LIEF::ELF::Header::FILE_TYPE(binary->header.file_type));
  hdr.machine_type(LIEF::ELF::ARCH(binary->header.machine_type));
  hdr.object_file_version(LIEF::ELF::Header::VERSION(binary->header.object_file_version));
  hdr.program_headers_offset(binary->header.program_headers_offset);
  hdr.section_headers_offset(binary->header.section_headers_offset);
  hdr.processor_flag(binary->header.processor_flags);
  hdr.header_size(binary->header.header_size);
  hdr.program_header_size(binary->header.program_header_size);
  hdr.numberof_segments(binary->header.numberof_segments);
  hdr.section_header_size(binary->header.section_header_size);
  hdr.numberof_sections(binary->header.numberof_sections);
  hdr.section_name_table_idx(binary->header.name_string_table_idx);
  hdr.entrypoint(binary->header.entrypoint);

  //TODO: identity
  return 1;
}


void elf_binary_destroy(Elf_Binary_t* binary) {
  destroy_sections(binary);
  destroy_segments(binary);
  destroy_dynamic_symbols(binary);
  destroy_symtab_symbols(binary);
  destroy_dynamic_entries(binary);

  if (binary->interpreter != nullptr) {
    free(const_cast<char*>(binary->interpreter));
  }

  delete reinterpret_cast<Binary*>(binary->handler);
  free(binary);

}
//}
