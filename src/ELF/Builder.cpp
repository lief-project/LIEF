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
#include <set>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <functional>
#include <map>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/ELF/Builder.hpp"
#include "Builder.tcc"

namespace LIEF {
namespace ELF {


Builder::~Builder(void) = default;

Builder::Builder(Binary *binary) :
  empties_gnuhash_{false},
  binary_{binary}
{
  this->ios_.reserve(binary->original_size());
}

void Builder::build(void) {
  if(this->binary_->type() == ELF_CLASS::ELFCLASS32) {
    this->build<ELF32>();
  } else {
    this->build<ELF64>();
  }
}

const std::vector<uint8_t>& Builder::get_build(void) {
  return this->ios_.raw();
}


Builder& Builder::empties_gnuhash(bool flag) {
  this->empties_gnuhash_ = flag;
  return *this;
}


void Builder::write(const std::string& filename) const {
  std::ofstream output_file{filename, std::ios::out | std::ios::binary | std::ios::trunc};
  if (output_file) {
    std::vector<uint8_t> content;
    this->ios_.get(content);

    std::copy(
        std::begin(content),
        std::end(content),
        std::ostreambuf_iterator<char>(output_file));
  }
}


void Builder::build_empty_symbol_gnuhash(void) {
  LOG(DEBUG) << "Build empty GNU Hash";
  auto&& it_gnuhash = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_GNU_HASH;
      });

  if (it_gnuhash == std::end(this->binary_->sections_)) {
    throw corrupted("Unable to find the .gnu.hash section");
  }

  Section* gnu_hash_section = *it_gnuhash;

  std::vector<uint8_t> content;
  const uint32_t nb_buckets = 1;
  const uint32_t shift2     = 0;
  const uint32_t maskwords  = 1;
  const uint32_t symndx     = 1; // 0 is reserved

  // nb_buckets
  content.insert(std::end(content),
    reinterpret_cast<const uint8_t*>(&nb_buckets),
    reinterpret_cast<const uint8_t*>(&nb_buckets) + sizeof(uint32_t));

  // symndx
  content.insert(std::end(content),
    reinterpret_cast<const uint8_t*>(&symndx),
    reinterpret_cast<const uint8_t*>(&symndx) + sizeof(uint32_t));

  // maskwords
  content.insert(std::end(content),
    reinterpret_cast<const uint8_t*>(&maskwords),
    reinterpret_cast<const uint8_t*>(&maskwords) + sizeof(uint32_t));

  // shift2
  content.insert(std::end(content),
    reinterpret_cast<const uint8_t*>(&shift2),
    reinterpret_cast<const uint8_t*>(&shift2) + sizeof(uint32_t));

  // fill with 0
  content.insert(
      std::end(content),
      gnu_hash_section->size() - content.size(),
      0);
  gnu_hash_section->content(content);

}





size_t Builder::note_offset(const Note& note) {
  auto&& it_note = std::find_if(
      std::begin(this->binary_->notes_),
      std::end(this->binary_->notes_),
      [&note] (const Note* n) {
        return *n == note;
      });
  if (it_note == std::end(this->binary_->notes_)) {
    // TODO
  }

  size_t offset = std::accumulate(
      std::begin(this->binary_->notes_),
      it_note, 0,
      [] (size_t offset, const Note* n) {
        return offset + n->size();
      });
  return offset;
}


void Builder::build(NOTE_TYPES type) {
  using note_to_section_map_t = std::multimap<NOTE_TYPES, const char*>;
  using value_t = typename note_to_section_map_t::value_type;

  static const note_to_section_map_t note_to_section_map = {
    { NOTE_TYPES::NT_GNU_ABI_TAG,      ".note.ABI-tag"          },
    { NOTE_TYPES::NT_GNU_ABI_TAG,      ".note.android.ident"    },

    { NOTE_TYPES::NT_GNU_BUILD_ID,     ".note.gnu.build-id"     },
    { NOTE_TYPES::NT_GNU_GOLD_VERSION, ".note.gnu.gold-version" },
  };

  Segment& segment_note = this->binary_->get(SEGMENT_TYPES::PT_NOTE);

  auto&& range_secname = note_to_section_map.equal_range(type);

  auto&& it_section_name = std::find_if(
      range_secname.first, range_secname.second,
      [this] (value_t p) {
        return this->binary_->has_section(p.second);
      });

  bool has_section = (it_section_name != range_secname.second);

  std::string section_name;
  if (has_section) {
    section_name = it_section_name->second;
  } else {
    section_name = range_secname.first->second;
  }

  // Link section and notes
  if (this->binary_->has(type) and
      has_section)
  {
    Section& section = this->binary_->get_section(section_name);
    const Note& note = this->binary_->get(type);
    section.offset(segment_note.file_offset() + this->note_offset(note));
    section.size(note.size());
  }

  // Remove the section
  if (not this->binary_->has(type) and
      has_section)
  {
    this->binary_->remove_section(section_name, true);
  }

  // Add a new section
  if (this->binary_->has(type) and
      not has_section)
  {

    const Note& note = this->binary_->get(type);

    Section section{section_name, ELF_SECTION_TYPES::SHT_NOTE};
    section += ELF_SECTION_FLAGS::SHF_ALLOC;

    Section& section_added = this->binary_->add(section, false);
    section_added.offset(segment_note.file_offset() + this->note_offset(note));
    section_added.size(note.size());
  }
}


}
}
