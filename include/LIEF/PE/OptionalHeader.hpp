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
#ifndef LIEF_PE_OPTIONALHEADER_H_
#define LIEF_PE_OPTIONALHEADER_H_
#include <iostream>
#include <set>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {
class Parser;

namespace details {
struct pe32_optional_header;
struct pe64_optional_header;
}

//! Class which represents the PE OptionalHeader structure
class LIEF_API OptionalHeader : public Object {
  friend class Parser;
  public:
  OptionalHeader();
  OptionalHeader(const details::pe32_optional_header& header);
  OptionalHeader(const details::pe64_optional_header& header);
  virtual ~OptionalHeader();

  OptionalHeader& operator=(const OptionalHeader&);
  OptionalHeader(const OptionalHeader&);
  //! Magic bytes (either ``PE32`` or ``PE32+`` for 64-bits PE files
  PE_TYPE magic() const;

  //! The linker major version
  uint8_t major_linker_version() const;

  //! The linker minor version
  uint8_t minor_linker_version() const;

  //! The size of the code ``.text`` section or the sum of
  //! all the sections that contain code (ie. PE::Section with the flag SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE)
  uint32_t sizeof_code() const;

  //! The size of the initialized data which are usually located in the ``.data`` section.
  //! If the initialized data are split across multiple sections, it is the sum of the sections.
  //!
  //! The sections associated with the initialized data are usually identified with the
  //! flag SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA
  uint32_t sizeof_initialized_data() const;

  //! The size of the uninitialized data which are usually located in the ``.bss`` section.
  //! If the uninitialized data are split across multiple sections, it is the sum of the sections.
  //!
  //! The sections associated with the uninitialized data are usually identified with the
  //! flag SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_UNINITIALIZED_DATA
  uint32_t sizeof_uninitialized_data() const;

  //! The address of the entry point relative to the image base when the executable file is
  //! loaded into memory. For program images, this is the starting address. For device
  //! drivers, this is the address of the initialization function.
  //!
  //! An entry point is optional for DLLs. When no entry point is present, this field must be zero.
  uint32_t addressof_entrypoint() const;

  //! Address relative to the imagebase where the binary's code starts.
  uint32_t baseof_code() const;

  //! Address relative to the imagebase where the binary's data starts.
  //!
  //! @warning This value is not present for PE64 files
  uint32_t baseof_data() const;

  //! The preferred base address when mapping the binary in memory
  uint64_t imagebase() const;

  //! The alignment (in bytes) of sections when they are loaded into memory.
  //!
  //! It must be greater than or equal to file_alignment and
  //! the default is the page size for the architecture.
  uint32_t section_alignment() const;

  //! The section's file alignment. This value must be a power of 2 between 512 and 64K.
  //! The default value is usually 512
  uint32_t file_alignment() const;

  //! The **major** version number of the required operating system
  uint16_t major_operating_system_version() const;

  //! The **minor** version number of the required operating system
  uint16_t minor_operating_system_version() const;

  //! The major version number of the image
  uint16_t major_image_version() const;

  //! The minor version number of the image
  uint16_t minor_image_version() const;

  //! The major version number of the subsystem
  uint16_t major_subsystem_version() const;

  //! The minor version number of the subsystem
  uint16_t minor_subsystem_version() const;

  //! According to the official PE specifications, this value
  //! is reserved and **should** be 0.
  uint32_t win32_version_value() const;

  //! The size (in bytes) of the image, including all headers, as the image is loaded in memory.
  //!
  //! It must be a multiple of section_alignment and should match Binary::virtual_size
  uint32_t sizeof_image() const;

  //! Size of the DosHeader + PE Header + Section headers rounded up to a multiple of the file_alignment
  uint32_t sizeof_headers() const;

  //! The image file checksum. The algorithm for computing the checksum is incorporated into ``IMAGHELP.DLL``.
  //!
  //! The following are checked for validation at load time all **drivers**, any **DLL loaded at boot**
  //! time, and any **DLL** that is loaded into a **critical** Windows process.
  uint32_t checksum() const;

  //! The re-computed value of the OptionalHeader::checksum.
  //! If both values do not match, it could mean that the binary has been modified
  //! after the compilation.
  //!
  //! This value is computed by LIEF when parsing the PE binary.
  inline uint32_t computed_checksum() const {
    return computed_checksum_;
  }

  //! Target subsystem like Driver, XBox, Windows GUI, ...
  SUBSYSTEM subsystem() const;

  //! Some characteristics of the underlying binary like the support of the PIE.
  //! The prefix ``dll`` comes from the official PE specifications but these characteristics
  //! are also used for **executables**
  uint32_t dll_characteristics() const;

  //! Size of the stack to reserve when loading the PE binary
  //!
  //! Only :attr:`~lief.PE.OptionalHeader.sizeof_stack_commit` is committed, the rest is made
  //! available one page at a time until the reserve size is reached.
  uint64_t sizeof_stack_reserve() const;

  //! Size of the stack to commit
  uint64_t sizeof_stack_commit() const;

  //! Size of the heap to reserve when loading the PE binary
  uint64_t sizeof_heap_reserve() const;

  //! Size of the heap to commit
  uint64_t sizeof_heap_commit() const;

  //! According to the PE specifications, this value is *reserved* and **should** be 0.
  uint32_t loader_flags() const;

  //! The number of DataDirectory that follow this header.
  uint32_t numberof_rva_and_size() const;

  //! Check if the given DLL_CHARACTERISTICS is included in the dll_characteristics
  bool has(DLL_CHARACTERISTICS c) const;

  //! Return the list of the dll_characteristics as an std::set of DLL_CHARACTERISTICS
  std::set<DLL_CHARACTERISTICS> dll_characteristics_list() const;

  //! Add a DLL_CHARACTERISTICS to the current characteristics
  void add(DLL_CHARACTERISTICS c);

  //! Remove a DLL_CHARACTERISTICS from the current characteristics
  void remove(DLL_CHARACTERISTICS c);

  void magic(PE_TYPE magic);
  void major_linker_version(uint8_t majorLinkerVersion);
  void minor_linker_version(uint8_t minorLinkerVersion);
  void sizeof_code(uint32_t sizeOfCode);
  void sizeof_initialized_data(uint32_t sizeOfInitializedData);
  void sizeof_uninitialized_data(uint32_t sizeOfUninitializedData);
  void addressof_entrypoint(uint32_t addressOfEntryPoint);
  void baseof_code(uint32_t baseOfCode);
  void baseof_data(uint32_t baseOfData);
  void imagebase(uint64_t imageBase);
  void section_alignment(uint32_t sectionAlignment);
  void file_alignment(uint32_t fileAlignment);
  void major_operating_system_version(uint16_t majorOperatingSystemVersion);
  void minor_operating_system_version(uint16_t minorOperatingSystemVersion);
  void major_image_version(uint16_t majorImageVersion);
  void minor_image_version(uint16_t minorImageVersion);
  void major_subsystem_version(uint16_t majorSubsystemVersion);
  void minor_subsystem_version(uint16_t minorSubsystemVersion);
  void win32_version_value(uint32_t win32VersionValue);
  void sizeof_image(uint32_t sizeOfImage);
  void sizeof_headers(uint32_t sizeOfHeaders);
  void checksum(uint32_t checkSum);
  void subsystem(SUBSYSTEM subsystem);
  void dll_characteristics(uint32_t DLLCharacteristics);
  void sizeof_stack_reserve(uint64_t sizeOfStackReserve);
  void sizeof_stack_commit(uint64_t sizeOfStackCommit);
  void sizeof_heap_reserve(uint64_t sizeOfHeapReserve);
  void sizeof_heap_commit(uint64_t sizeOfHeapCommit);
  void loader_flags(uint32_t loaderFlags);
  void numberof_rva_and_size(uint32_t numberOfRvaAndSize);

  void accept(Visitor& visitor) const override;

  OptionalHeader& operator+=(DLL_CHARACTERISTICS c);
  OptionalHeader& operator-=(DLL_CHARACTERISTICS c);

  bool operator==(const OptionalHeader& rhs) const;
  bool operator!=(const OptionalHeader& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const OptionalHeader& entry);

  private:
  PE_TYPE   magic_;
  uint8_t   majorLinkerVersion_;
  uint8_t   minorLinkerVersion_;
  uint32_t  sizeOfCode_;
  uint32_t  sizeOfInitializedData_;
  uint32_t  sizeOfUninitializedData_;
  uint32_t  addressOfEntryPoint_; // RVA
  uint32_t  baseOfCode_;          // RVA
  uint32_t  baseOfData_;          //Not present in PE32+
  uint64_t  imageBase_;
  uint32_t  sectionAlignment_;
  uint32_t  fileAlignment_;
  uint16_t  majorOperatingSystemVersion_;
  uint16_t  minorOperatingSystemVersion_;
  uint16_t  majorImageVersion_;
  uint16_t  minorImageVersion_;
  uint16_t  majorSubsystemVersion_;
  uint16_t  minorSubsystemVersion_;
  uint32_t  win32VersionValue_;
  uint32_t  sizeOfImage_;
  uint32_t  sizeOfHeaders_;
  uint32_t  checkSum_;
  SUBSYSTEM subsystem_;
  uint32_t  DLLCharacteristics_;
  uint64_t  sizeOfStackReserve_;
  uint64_t  sizeOfStackCommit_;
  uint64_t  sizeOfHeapReserve_;
  uint64_t  sizeOfHeapCommit_;
  uint32_t  loaderFlags_;
  uint32_t  numberOfRvaAndSize_;

  uint32_t  computed_checksum_ = 0;
};
}
}

#endif
