/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"


namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CoreFile::parse_(void) {
  using Elf_Addr  = typename ELF_T::Elf_Addr;
  using Elf_FileEntry  = typename ELF_T::Elf_FileEntry;

  const VectorStream& stream(this->description());
  if (not stream.can_read<Elf_Addr>(0)) {
    return;
  }
  const Elf_Addr count = stream.read_conv<Elf_Addr>();
  if (count == 0 or not stream.can_read<Elf_Addr>()) {
    return;
  }
  this->page_size_ = static_cast<uint64_t>(stream.read_conv<Elf_Addr>());
  for (uint32_t idx = 0; idx < count; idx++) {
    if (not stream.can_read<Elf_FileEntry>()) {
      break;
    }
    const Elf_FileEntry entry = stream.read_conv<Elf_FileEntry>();
    this->files_.push_back({entry.start, entry.end, entry.file_ofs, {}});
  }
  for (uint32_t idx = 0; idx < count; idx++) {
    this->files_[idx].path = stream.read_string();
  }
}

template <typename ELF_T>
void CoreFile::build_(void) {
  using Elf_Addr  = typename ELF_T::Elf_Addr;
  using Elf_FileEntry  = typename ELF_T::Elf_FileEntry;

  Note::description_t& description = this->description();

  Elf_Addr count = static_cast<Elf_Addr>(this->count());
  Elf_Addr page_size = static_cast<Elf_Addr>(this->page_size_);

  vector_iostream raw_output;
  size_t desc_part_size = sizeof(Elf_Addr) * 2 + count * sizeof(Elf_FileEntry);
  raw_output.reserve(desc_part_size);

  raw_output.write_conv<Elf_Addr>(count);
  raw_output.write_conv<Elf_Addr>(page_size);
  for (const CoreFileEntry& entry: this->files_) {
    const Elf_FileEntry raw_entry = {
      static_cast<Elf_Addr>(entry.start),
      static_cast<Elf_Addr>(entry.end),
      static_cast<Elf_Addr>(entry.file_ofs)
    };
    raw_output.write_conv<Elf_FileEntry>(raw_entry);
  }
  for (const CoreFileEntry& entry: this->files_) {
    raw_output.write(entry.path);
  }
  description = std::move(raw_output.raw());
}

} // namespace ELF
} // namespace LIEF
