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
#ifndef LIEF_PE_OPTIONALHEADER_H_
#define LIEF_PE_OPTIONALHEADER_H_
#include <iostream>
#include <set>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {
class LIEF_API OptionalHeader : public Object {
  public:
    OptionalHeader(void);
    OptionalHeader(const pe32_optional_header *header);
    OptionalHeader(const pe64_optional_header *header);
    virtual ~OptionalHeader(void);

    OptionalHeader& operator=(const OptionalHeader&);
    OptionalHeader(const OptionalHeader&);

    PE_TYPE   magic(void) const;
    uint8_t   major_linker_version(void) const;
    uint8_t   minor_linker_version(void) const;
    uint32_t  sizeof_code(void) const;
    uint32_t  sizeof_initialized_data(void) const;
    uint32_t  sizeof_uninitialized_data(void) const;
    uint32_t  addressof_entrypoint(void) const;
    uint32_t  baseof_code(void) const;
    uint32_t  baseof_data(void) const;
    uint64_t  imagebase(void) const;
    uint32_t  section_alignment(void) const;
    uint32_t  file_alignment(void) const;
    uint16_t  major_operating_system_version(void) const;
    uint16_t  minor_operating_system_version(void) const;
    uint16_t  major_image_version(void) const;
    uint16_t  minor_image_version(void) const;
    uint16_t  major_subsystem_version(void) const;
    uint16_t  minor_subsystem_version(void) const;
    uint32_t  win32_version_value(void) const;
    uint32_t  sizeof_image(void) const;
    uint32_t  sizeof_headers(void) const;
    uint32_t  checksum(void) const;
    SUBSYSTEM subsystem(void) const;
    uint32_t  dll_characteristics(void) const;
    uint64_t  sizeof_stack_reserve(void) const;
    uint64_t  sizeof_stack_commit(void) const;
    uint64_t  sizeof_heap_reserve(void) const;
    uint64_t  sizeof_heap_commit(void) const;
    uint32_t  loader_flags(void) const;
    uint32_t  numberof_rva_and_size(void) const;
    bool      has(DLL_CHARACTERISTICS c) const;
    std::set<DLL_CHARACTERISTICS> dll_characteristics_list(void) const;

    void add(DLL_CHARACTERISTICS c);
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

    virtual void accept(Visitor& visitor) const override;

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
};
}
}

#endif
