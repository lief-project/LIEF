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
#ifndef LIEF_MACHO_DYLD_CHAINED_FIXUPS_H
#define LIEF_MACHO_DYLD_CHAINED_FIXUPS_H
#include <memory>
#include "LIEF/span.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/visibility.h"
#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class Builder;
class ChainedBindingInfo;
class LinkEdit;

namespace details {
struct linkedit_data_command;
struct dyld_chained_fixups_header;
struct dyld_chained_starts_in_segment;
}

//! Class that represents the LC_DYLD_CHAINED_FIXUPS command
//!
//! This command aims at providing rebase and binding information like
//! the DyldInfo's bytecode. Compared to the DyldInfo bytecode, these chained
//! fixups are taking less space.
class LIEF_API DyldChainedFixups : public LoadCommand {
  friend class BinaryParser;
  friend class Builder;
  friend class LinkEdit;

  public:
  //! Structure that mirrors the raw dyld_chained_starts_in_segment
  //! which aims at providing information about the chained rebase/bind fixups
  //!
  //! The relocations provided by this structure can be accessed through SegmentCommand::relocations
  struct chained_starts_in_segment {
    uint32_t offset            = 0; ///< Original offset of the structure, relative to DyldChainedFixups::starts_offset
    uint32_t size              = 0; ///< sizeof(size) + sizeof(page_size) + ... + sizeof(pointer_format)
    uint16_t page_size         = 0; ///< Likely 0x1000 for x86/x86_64 architectures and 0x4000 for ARM64 architecture
    uint64_t segment_offset    = 0; ///< Offset of the segment's data from the beginning of the file (it should match SegmentCommand::file_offset)
    uint32_t max_valid_pointer = 0; ///< for 32-bit OS, any value beyond this is not a pointer
    DYLD_CHAINED_PTR_FORMAT pointer_format; ///< How pointers are encoded

    //! How many pages are in the page_start array
    inline size_t page_count() const {
      return page_start.size();
    }

    std::vector<uint16_t> page_start;   ///< Offset in the SegmentCommand of the first element of the chain
    std::vector<uint16_t> chain_starts; ///< Currently not supported

    SegmentCommand& segment; ///< Segment in which the rebase/bind fixups take place

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const chained_starts_in_segment& info);

    private:
    friend class BinaryParser;
    chained_starts_in_segment(uint32_t offset, SegmentCommand& segment);
    chained_starts_in_segment(uint32_t offset, const details::dyld_chained_starts_in_segment& info,
                              SegmentCommand& segment);
  };

  //! Internal container for storing chained_starts_in_segment
  using chained_starts_in_segments_t = std::vector<chained_starts_in_segment>;

  //! Iterator that outputs chained_starts_in_segment&
  using it_chained_starts_in_segments_t = ref_iterator<chained_starts_in_segments_t&>;

  //! Iterator that outputs const chained_starts_in_segment&
  using it_const_chained_starts_in_segments_t = const_ref_iterator<const chained_starts_in_segments_t&>;

  //! Internal container for storing DyldBindingInfo
  using binding_info_t = std::vector<std::unique_ptr<ChainedBindingInfo>>;

  //! Iterator which outputs DyldBindingInfo&
  using it_binding_info = ref_iterator<binding_info_t&, ChainedBindingInfo*>;

  //! Iterator which outputs const DyldBindingInfo&
  using it_const_binding_info = const_ref_iterator<const binding_info_t&, ChainedBindingInfo*>;


  DyldChainedFixups();
  DyldChainedFixups(const details::linkedit_data_command& cmd);
  DyldChainedFixups* clone() const override;

  ~DyldChainedFixups() override;

  //! Offset of the LC_DYLD_CHAINED_FIXUPS chained payload.
  //! This offset should point in the __LINKEDIT segment
  uint32_t data_offset() const;

  //! Size of the LC_DYLD_CHAINED_FIXUPS payload.
  uint32_t data_size() const;

  void data_offset(uint32_t offset);
  void data_size(uint32_t size);

  //! Iterator over the bindings (ChainedBindingInfo) associated with this command
  inline it_binding_info bindings() {
    return bindings_;
  }

  //! Iterator over the bindings (ChainedBindingInfo) associated with this command
  inline it_const_binding_info bindings() const {
    return bindings_;
  }

  //! Iterator over the chained fixup metadata
  inline it_chained_starts_in_segments_t chained_starts_in_segments() {
    return chained_starts_in_segment_;
  }

  inline it_const_chained_starts_in_segments_t chained_starts_in_segments() const {
    return chained_starts_in_segment_;
  }

  //! Chained fixups version. The loader (dyld v852.2) checks
  //! that this value is set to 0
  inline uint32_t fixups_version() const { return fixups_version_; }
  inline void fixups_version(uint32_t version) { fixups_version_ = version; }

  //! offset of dyld_chained_starts_in_image in chain_data
  inline uint32_t starts_offset() const { return starts_offset_; }
  inline void starts_offset(uint32_t offset) { starts_offset_ = offset; }

  //! Offset of imports table in chain data
  inline uint32_t imports_offset() const { return imports_offset_; }
  inline void imports_offset(uint32_t offset) { imports_offset_ = offset; }

  //! Offset of symbol strings in chain data
  inline uint32_t symbols_offset() const { return symbols_offset_; }
  inline void symbols_offset(uint32_t offset) { symbols_offset_ = offset; }

  //! Number of imported symbol names
  inline uint32_t imports_count() const { return imports_count_; }
  inline void imports_count(uint32_t cnt) { imports_count_ = cnt; }

  //! The compression algorithm (if any) used to store the symbols
  //! 0 means uncompressed while 1 means zlib compressed.
  //!
  //! As far of the version v852.2 of dyld loader, it only supports
  //! **uncompressed** format
  inline uint32_t symbols_format() const { return symbols_format_; }
  inline void symbols_format(uint32_t fmt) { symbols_format_ = fmt; }

  //! The format of the imports (ChainedBindingInfo)
  inline DYLD_CHAINED_FORMAT imports_format() const { return imports_format_; }
  inline void imports_format(DYLD_CHAINED_FORMAT fmt) { imports_format_ = fmt; }

  bool operator==(const DyldChainedFixups& rhs) const;
  bool operator!=(const DyldChainedFixups& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  void update_with(const details::dyld_chained_fixups_header& header);
  DyldChainedFixups& operator=(const DyldChainedFixups& other);
  DyldChainedFixups(const DyldChainedFixups& other);

  uint32_t data_offset_ = 0;
  uint32_t data_size_   = 0;

  // Raw payload of the DyldChainedFixups.
  // This payload is located in the __LINKEDIT segment
  span<uint8_t> content_;

  uint32_t fixups_version_ = 0;
  uint32_t starts_offset_  = 0;
  uint32_t imports_offset_ = 0;
  uint32_t symbols_offset_ = 0;
  uint32_t imports_count_  = 0;
  uint32_t symbols_format_ = 0;
  DYLD_CHAINED_FORMAT imports_format_ = DYLD_CHAINED_FORMAT::IMPORT;

  chained_starts_in_segments_t chained_starts_in_segment_;

  binding_info_t bindings_;
};

}
}
#endif
