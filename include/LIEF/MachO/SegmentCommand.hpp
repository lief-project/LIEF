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
#ifndef LIEF_MACHO_SEGMENT_COMMAND_H_
#define LIEF_MACHO_SEGMENT_COMMAND_H_

#include <string>
#include <vector>
#include <iostream>
#include <functional>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/type_traits.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/Section.hpp"


namespace LIEF {
namespace MachO {
class BinaryParser;
class Binary;

//! @class SegmentCommand
//! @brief Class which represent a MachO Segment
class LIEF_API SegmentCommand : public LoadCommand {

  friend class BinaryParser;
  friend class Binary;

  public:
  using content_t = std::vector<uint8_t>;

  public:
  SegmentCommand(void);
  SegmentCommand(const segment_command_32 *segmentCmd);
  SegmentCommand(const segment_command_64 *segmentCmd);

  SegmentCommand& operator=(SegmentCommand other);
  SegmentCommand(const SegmentCommand& copy);

  SegmentCommand(const std::string& name, const content_t& content);
  SegmentCommand(const std::string& name);

  void swap(SegmentCommand& other);

  virtual SegmentCommand* clone(void) const override;

  virtual ~SegmentCommand(void);

  const std::string& name(void) const;
  uint64_t virtual_address(void) const;
  uint64_t virtual_size(void) const;
  uint64_t file_size(void) const;
  uint64_t file_offset(void) const;
  uint32_t max_protection(void) const;
  uint32_t init_protection(void) const;
  uint32_t numberof_sections(void) const;
  uint32_t flags(void) const;
  it_sections       sections(void);
  it_const_sections sections(void) const;

  it_relocations       relocations(void);
  it_const_relocations relocations(void) const;

  const content_t& content(void) const;

  void name(const std::string& name);
  void virtual_address(uint64_t virtualAddress);
  void virtual_size(uint64_t virtualSize);
  void file_offset(uint64_t fileOffset);
  void file_size(uint64_t fileSize);
  void max_protection(uint32_t maxProtection);
  void init_protection(uint32_t initProtection);
  void numberof_sections(uint32_t nbSections);
  void flags(uint32_t flags);
  void content(const content_t& data);

  Section& add_section(const Section& section);

  void remove_all_sections(void);

  bool has(const Section& section) const;
  bool has_section(const std::string& section_name) const;

  bool operator==(const SegmentCommand& rhs) const;
  bool operator!=(const SegmentCommand& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  virtual void accept(Visitor& visitor) const override;

  private:
  std::string name_;

  //! @brief Indicates the starting virtual memory address of this segmen
  uint64_t virtualAddress_{0};

  //! @brief Indicates the number of bytes of virtual memory occupied by this segment. See also the description of filesize, below.
  uint64_t virtualSize_{0};

  //! @brief Indicates the offset in this file of the data to be mapped at virtualAddress_.
  uint64_t fileOffset_{0};

  uint64_t fileSize_{0};

  uint32_t maxProtection_{0};

  uint32_t initProtection_{0};

  uint32_t nbSections_{0};

  uint32_t flags_{0};

  content_t data_;

  sections_t    sections_;

  relocations_t relocations_;


};

}
}
#endif
