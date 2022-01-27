/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#ifndef LIEF_ELF_SEGMENT_H_
#define LIEF_ELF_SEGMENT_H_

#include <string>
#include <vector>
#include <iostream>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {
class Handler;
}

class Parser;
class Binary;
class Section;

namespace details {
struct Elf64_Phdr;
struct Elf32_Phdr;
}

//! Class which represents the ELF segments
class LIEF_API Segment : public Object {

  friend class Parser;
  friend class Section;
  friend class Binary;

  public:
  Segment();
  Segment(const std::vector<uint8_t>& header, ELF_CLASS type);
  Segment(const std::vector<uint8_t>& header);
  Segment(const details::Elf64_Phdr& header);
  Segment(const details::Elf32_Phdr& header);
  virtual ~Segment();

  Segment& operator=(Segment other);
  Segment(const Segment& other);
  void swap(Segment& other);

  //! The segment's type (LOAD, DYNAMIC, ...)
  SEGMENT_TYPES type() const;

  //! The flag permissions associated with this segment
  ELF_SEGMENT_FLAGS flags() const;

  //! The file offset of the data associated with this segment
  uint64_t file_offset() const;

  //! The virtual address of the segment.
  uint64_t virtual_address() const;

  //! The physical address of the segment.
  //! This value is not really relevant on systems like Linux or Android.
  //! On the other hand, Qualcomm trustlets might use this value.
  //!
  //! Usually this value matches virtual_address
  uint64_t physical_address() const;

  //! The **file** size of the data associated with this segment
  uint64_t physical_size() const;

  //! The in-memory size of this segment.
  //! Usually, if the ``.bss`` segment is wrapped by this segment
  //! then, virtual_size is larger than physical_size
  uint64_t virtual_size() const;

  //! The offset alignment of the segment
  uint64_t alignment() const;

  //! The raw data associated with this segment.
  std::vector<uint8_t> content() const;

  //! Check if the current segment has the given flag
  bool has(ELF_SEGMENT_FLAGS flag) const;

  //! Check if the current segment wraps the given ELF::Section
  bool has(const Section& section) const;

  //! Check if the current segment wraps the given section's name
  bool has(const std::string& section_name) const;

  //! Append the given ELF_SEGMENT_FLAGS
  void add(ELF_SEGMENT_FLAGS flag);

  //! Remove the given ELF_SEGMENT_FLAGS
  void remove(ELF_SEGMENT_FLAGS flag);

  void type(SEGMENT_TYPES type);
  void flags(ELF_SEGMENT_FLAGS flags);
  void clear_flags();
  void file_offset(uint64_t file_offset);
  void virtual_address(uint64_t virtual_address);
  void physical_address(uint64_t physical_address);
  void physical_size(uint64_t physical_size);
  void virtual_size(uint64_t virtual_size);
  void alignment(uint64_t alignment);
  void content(const std::vector<uint8_t>& content);
  void content(std::vector<uint8_t>&& content);

  template<typename T> T get_content_value(size_t offset) const;
  template<typename T> void set_content_value(size_t offset, T value);
  size_t get_content_size() const;

  //! Iterator over the sections wrapped by this segment
  it_sections       sections();
  it_const_sections sections() const;

  void accept(Visitor& visitor) const override;

  Segment& operator+=(ELF_SEGMENT_FLAGS flag);
  Segment& operator-=(ELF_SEGMENT_FLAGS flag);

  bool operator==(const Segment& rhs) const;
  bool operator!=(const Segment& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Segment& segment);

  private:
  SEGMENT_TYPES         type_;
  ELF_SEGMENT_FLAGS     flags_;
  uint64_t              file_offset_;
  uint64_t              virtual_address_;
  uint64_t              physical_address_;
  uint64_t              size_;
  uint64_t              virtual_size_;
  uint64_t              alignment_;
  sections_t            sections_;
  DataHandler::Handler* datahandler_{nullptr};
  std::vector<uint8_t>  content_c_;
};


}
}
#endif /* _ELF_SEGMENT_H_ */
