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
#ifndef LIEF_ELF_SECTION_H_
#define LIEF_ELF_SECTION_H_

#include <string>
#include <vector>
#include <iostream>
#include <set>

#include "LIEF/visibility.h"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/ELF/enums.hpp"
#include "LIEF/iterators.hpp"

namespace LIEF {
namespace ELF {

namespace DataHandler {
class Handler;
}

class Segment;
class Parser;
class Binary;
class Builder;
class ExeLayout;
class ObjectFileLayout;

namespace details {
struct Elf64_Shdr;
struct Elf32_Shdr;
}

//! Class wich represents an ELF Section
class LIEF_API Section : public LIEF::Section {
  friend class Parser;
  friend class Binary;
  friend class Builder;
  friend class ExeLayout;
  friend class ObjectFileLayout;

  public:
  using segments_t        = std::vector<Segment*>;
  using it_segments       = ref_iterator<segments_t&>;
  using it_const_segments = const_ref_iterator<const segments_t&>;

  Section(const uint8_t *data, ELF_CLASS type);
  Section(const details::Elf64_Shdr& header);
  Section(const details::Elf32_Shdr& header);
  Section(const std::string& name, ELF_SECTION_TYPES type = ELF_SECTION_TYPES::SHT_PROGBITS);

  Section();
  ~Section() override;

  Section& operator=(Section other);
  Section(const Section& other);
  void swap(Section& other);

  ELF_SECTION_TYPES type() const;

  //! Section's content
  span<const uint8_t> content() const override;

  //! Set section content
  void content(const std::vector<uint8_t>& data) override;

  void content(std::vector<uint8_t>&& data);

  //! Section flags LIEF::ELF::ELF_SECTION_FLAGS
  uint64_t flags() const;

  //! ``True`` if the section has the given flag
  //!
  //! @param[in] flag flag to test
  bool has(ELF_SECTION_FLAGS flag) const;

  //! ``True`` if the section is wrapped by the given Segment
  bool has(const Segment& segment) const;

  //! Return section flags as a ``std::set``
  std::set<ELF_SECTION_FLAGS> flags_list() const;

  uint64_t size() const override;

  void size(uint64_t size) override;

  void offset(uint64_t offset) override;

  uint64_t offset() const override;


  //! @see offset
  uint64_t file_offset() const;

  //! Original size of the section's data.
  //!
  //! This value is used by the ELF::Builder to determines if it needs
  //! to be relocated to avoid an override of the data
  uint64_t original_size() const;

  //! Section file alignment
  uint64_t alignment() const;

  //! Section information.
  //! This meaning of this value depends on the section's type
  uint64_t information() const;

  //! This function returns the size of an element in the case of a section that contains
  //! an array.
  //
  //! For instance, the `.dynamic` section contains an array of DynamicEntry. As the
  //! size of the raw C structure of this entry is 0x10 (``sizeof(Elf64_Dyn)``)
  //! in a ELF64, the `entry_size` is set to this value.
  uint64_t entry_size() const;

  //! Index to another section
  uint32_t link() const;

  //! Clear the content of the section with the given ``value``
  Section& clear(uint8_t value = 0);

  //! Add the given ELF_SECTION_FLAGS
  void add(ELF_SECTION_FLAGS flag);

  //! Remove the given ELF_SECTION_FLAGS
  void remove(ELF_SECTION_FLAGS flag);

  void type(ELF_SECTION_TYPES type);
  void flags(uint64_t flags);
  void clear_flags();
  void file_offset(uint64_t offset);
  void link(uint32_t link);
  void information(uint32_t info);
  void alignment(uint64_t alignment);
  void entry_size(uint64_t entry_size);

  it_segments       segments();
  it_const_segments segments() const;

  inline Section& as_frame() {
    is_frame_ = true;
    return *this;
  }

  inline bool is_frame() const {
    return is_frame_;
  }

  void accept(Visitor& visitor) const override;

  Section& operator+=(ELF_SECTION_FLAGS c);
  Section& operator-=(ELF_SECTION_FLAGS c);

  bool operator==(const Section& rhs) const;
  bool operator!=(const Section& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:
  span<uint8_t> writable_content();
  ELF_SECTION_TYPES     type_ = ELF_SECTION_TYPES::SHT_PROGBITS;
  uint64_t              flags_ = 0;
  uint64_t              original_size_ = 0;
  uint32_t              link_ = 0;
  uint32_t              info_ = 0;
  uint64_t              address_align_ = 0x1000;
  uint64_t              entry_size_ = 0;
  segments_t            segments_;
  bool                  is_frame_ = false;
  DataHandler::Handler* datahandler_ = nullptr;
  std::vector<uint8_t>  content_c_;
};

}
}
#endif /* _ELF_SECTION_H_ */
