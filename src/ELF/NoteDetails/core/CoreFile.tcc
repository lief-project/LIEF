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
#include <limits>

#include "logging.hpp"
#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"


namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CoreFile::parse_() {
  using Elf_Addr  = typename ELF_T::Elf_Addr;
  using Elf_FileEntry  = typename ELF_T::Elf_FileEntry;

  VectorStream stream{description()};

  auto res_count = stream.read_conv<Elf_Addr>();
  if (!res_count) {
    return;
  }

  const auto count = *res_count;
  const auto res_page_size = stream.read_conv<Elf_Addr>();

  if (!res_page_size) {
    LIEF_ERR("Can't read CoreFile.page_size");
    return;
  }

  page_size_ = *res_page_size;

  for (uint32_t idx = 0; idx < count; idx++) {
    auto res_entry = stream.read_conv<Elf_FileEntry>();
    if (!res_entry) {
      break;
    }
    const auto entry = *res_entry;
    files_.push_back({entry.start, entry.end, entry.file_ofs, {}});
  }

  for (uint32_t idx = 0; idx < count; idx++) {
    auto res_path = stream.read_string();
    if (!res_path) {
      break;
    }
    std::string path = std::move(*res_path);
    if (!path.empty()) {
      files_[idx].path = std::move(path);
    }
  }
}

template <typename ELF_T>
void CoreFile::build_() {
  using Elf_Addr  = typename ELF_T::Elf_Addr;
  using Elf_FileEntry  = typename ELF_T::Elf_FileEntry;

  Note::description_t& desc = description();

  auto cnt = static_cast<Elf_Addr>(count());
  auto page_size = static_cast<Elf_Addr>(page_size_);

  vector_iostream raw_output;
  size_t desc_part_size = sizeof(Elf_Addr) * 2 + cnt * sizeof(Elf_FileEntry);
  raw_output.reserve(desc_part_size);

  raw_output.write_conv<Elf_Addr>(cnt);
  raw_output.write_conv<Elf_Addr>(page_size);
  for (const CoreFileEntry& entry: files_) {
    const Elf_FileEntry raw_entry = {
      static_cast<Elf_Addr>(entry.start),
      static_cast<Elf_Addr>(entry.end),
      static_cast<Elf_Addr>(entry.file_ofs)
    };
    raw_output.write_conv<Elf_FileEntry>(raw_entry);
  }
  for (const CoreFileEntry& entry: files_) {
    raw_output.write(entry.path);
  }
  desc = std::move(raw_output.raw());
}

} // namespace ELF
} // namespace LIEF
