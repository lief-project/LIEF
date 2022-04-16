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
#ifndef LIEF_MACHO_SEGMENT_COMMAND_H_
#define LIEF_MACHO_SEGMENT_COMMAND_H_

#include <string>
#include <vector>
#include <iostream>
#include <memory>

#include "LIEF/span.hpp"
#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/iterators.hpp"
#include "LIEF/MachO/LoadCommand.hpp"


namespace LIEF {
namespace MachO {

class BinaryParser;
class Binary;
class Builder;
class Section;
class Relocation;
class DyldInfo;

namespace details {
struct segment_command_32;
struct segment_command_64;
}

//! Class which represents a LOAD_COMMAND_TYPES::LC_SEGMENT / LOAD_COMMAND_TYPES::LC_SEGMENT_64 command
class LIEF_API SegmentCommand : public LoadCommand {

  friend class BinaryParser;
  friend class Binary;
  friend class Section;
  friend class Builder;

  public:
  using content_t = std::vector<uint8_t>;

  //! Internal container for storing Mach-O Section
  using sections_t = std::vector<std::unique_ptr<Section>>;

  //! Iterator which outputs Section&
  using it_sections = ref_iterator<sections_t&, Section*>;

  //! Iterator which outputs const Section&
  using it_const_sections = const_ref_iterator<const sections_t&, const Section*>;

  //! Internal container for storing Mach-O Relocation
  using relocations_t = std::vector<std::unique_ptr<Relocation>>;

  //! Iterator which outputs Relocation&
  using it_relocations = ref_iterator<relocations_t&, Relocation*>;

  //! Iterator which outputs const Relocation&
  using it_const_relocations = const_ref_iterator<const relocations_t&, const Relocation*>;

  public:
  SegmentCommand();
  SegmentCommand(const details::segment_command_32& cmd);
  SegmentCommand(const details::segment_command_64& cmd);

  SegmentCommand& operator=(SegmentCommand other);
  SegmentCommand(const SegmentCommand& copy);

  SegmentCommand(std::string name, content_t content);
  SegmentCommand(std::string name);

  void swap(SegmentCommand& other);

  SegmentCommand* clone() const override;

  virtual ~SegmentCommand();

  //! Name of the segment (e.g. ``__TEXT``)
  const std::string& name() const;

  //! Absolute virtual base address of the segment
  uint64_t virtual_address() const;

  //! Virtual size of the segment
  uint64_t virtual_size() const;

  //! Size of this segment in the binary file
  uint64_t file_size() const;

  //! Offset of the data of this segment in the file
  uint64_t file_offset() const;

  //! The maximum of protections for this segment (cf. VM_PROTECTIONS)
  uint32_t max_protection() const;

  //! The initial protections of this segment (cf. VM_PROTECTIONS)
  uint32_t init_protection() const;

  //! The number of sections associated with this segment
  uint32_t numberof_sections() const;

  //! Flags associated with this segment (cf. MACHO_SEGMENTS_FLAGS)
  uint32_t flags() const;

  //! Return an iterator over the MachO::Section linked to this segment
  it_sections sections();
  it_const_sections sections() const;

  //! Return an iterator over the MachO::Relocation linked to this segment
  //!
  //! For Mach-O executable or library this iterator should be empty as
  //! the relocations are managed by the Dyld::rebase_opcodes.
  //! On the other hand, for object files (``.o``) this iterator should not be empty
  it_relocations relocations();
  it_const_relocations relocations() const;

  //! Get the section with the given name
  const Section* get_section(const std::string& name) const;
  Section* get_section(const std::string& name);

  //! The raw content of this segment
  inline span<const uint8_t> content() const {
    return data_;
  }

  //! The original index of this segment
  inline int8_t index() const {
    return this->index_;
  }

  void name(const std::string& name);
  void virtual_address(uint64_t virtual_address);
  void virtual_size(uint64_t virtual_size);
  void file_offset(uint64_t file_offset);
  void file_size(uint64_t file_size);
  void max_protection(uint32_t max_protection);
  void init_protection(uint32_t init_protection);
  void numberof_sections(uint32_t nb_section);
  void flags(uint32_t flags);
  void content(content_t data);

  //! Add a new section in this segment
  Section& add_section(const Section& section);

  //! Remove all the sections linked to this segment
  void remove_all_sections();

  //! Check if the current segment embeds the given section
  bool has(const Section& section) const;

  //! Check if the current segment embeds the given section name
  bool has_section(const std::string& section_name) const;

  bool operator==(const SegmentCommand& rhs) const;
  bool operator!=(const SegmentCommand& rhs) const;

  std::ostream& print(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  static bool classof(const LoadCommand* cmd);

  protected:
  inline span<uint8_t> writable_content() {
    return data_;
  }

  void content_resize(size_t size);
  void content_insert(size_t where, size_t size);

  inline void content_extend(size_t width) {
    content_resize(data_.size() + width);
  }

  using update_fnc_t    = std::function<void(std::vector<uint8_t>&)>;
  using update_fnc_ws_t = std::function<void(std::vector<uint8_t>&, size_t, size_t)>;

  LIEF_LOCAL virtual void update_data(update_fnc_t f);
  LIEF_LOCAL virtual void update_data(update_fnc_ws_t f, size_t where, size_t size);

  std::string name_;
  uint64_t virtual_address_ = 0;
  uint64_t virtual_size_ = 0;
  uint64_t file_offset_ = 0;
  uint64_t file_size_ = 0;
  uint32_t max_protection_ = 0;
  uint32_t init_protection_ = 0;
  uint32_t nb_sections_ = 0;
  uint32_t flags_ = 0;
  int8_t  index_ = -1;
  content_t data_;
  sections_t sections_;
  relocations_t relocations_;
};

}
}
#endif
