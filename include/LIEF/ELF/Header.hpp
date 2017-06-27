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
#ifndef LIEF_ELF_HEADER_H_
#define LIEF_ELF_HEADER_H_

#include <iostream>
#include <array>
#include <vector>

#include "LIEF/Visitable.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/enums.hpp"

#include "LIEF/ELF/Structures.hpp"

namespace LIEF {
namespace ELF {
class DLL_PUBLIC Header : public Visitable {

  public:
    using identity_t = std::array<uint8_t, IDENTITY::EI_NIDENT>;

    Header(void);
    Header(const std::vector<uint8_t>& header);
    Header(const Elf32_Ehdr *header);
    Header(const Elf64_Ehdr *header);

    Header& operator=(const Header& copy);
    Header(const Header& copy);

    virtual ~Header(void);

    //! @brief Define the object file type. (e.g. executable, library...)
    E_TYPE    file_type(void) const;

    //! @brief LIEF abstract object type
    OBJECT_TYPES abstract_object_type(void) const;

    //! @brief Target architecture
    ARCH      machine_type(void) const;

    //! @brief LIEF abstract architecture
    std::pair<ARCHITECTURES, std::set<MODES>> abstract_architecture(void) const;

    //! @brief LIEF abstract endianness
    ENDIANNESS abstract_endianness(void) const;

    //! @brief Version of the object file format
    VERSION   object_file_version(void) const;
    uint64_t  entrypoint(void) const;
    uint64_t  program_headers_offset(void) const;
    uint64_t  section_headers_offset(void) const;
    uint32_t  processor_flag(void) const;

    //! @brief Size of the current header
    //!
    //! This size should be 64 for a ``ELF64`` binary and 52 for
    //! a ``ELF32`` one.
    uint32_t header_size(void) const;

    //! @brief Return the size of a ``Segment header``
    //!
    //! This size should be 56 for a ``ELF64`` binary and 32 for
    //! a ``ELF32`` one.
    uint32_t program_header_size(void) const;

    //! @brief Return the the number of segment's headers
    //! registred in the header
    uint32_t numberof_segments(void) const;


    //! @brief Return the size of a ``Section header``
    //!
    //! This size should be 64 for a ``ELF64`` binary and 40 for
    //! a ``ELF32`` one.
    uint32_t sizeof_section_header(void) const;

    //! @brief Return the the number of sections's headers
    //! registred in the header
    //!
    //! @warning Could differ from the real number of sections
    //! present in the binary
    uint32_t numberof_sections(void) const;

    //! @brief Return the section's index which holds
    //! section's names
    uint32_t section_name_table_idx(void) const;

    identity_t&       identity(void);
    const identity_t& identity(void) const;

    //! @brief Return the object's class. ``ELF64`` or ``ELF32``
    ELF_CLASS identity_class(void) const;

    //! @brief Specify the data encoding
    ELF_DATA identity_data(void) const;

    //! @see object_file_version
    VERSION identity_version(void) const;

    //! @brief Identifies the version of the ABI for which the object is prepared
    OS_ABI identity_os_abi(void) const;

    void file_type(E_TYPE type);
    void machine_type(ARCH machineType);
    void object_file_version(VERSION version);
    void entrypoint(uint64_t entryPoint);
    void program_headers_offset(uint64_t programHeaderOffset);
    void section_headers_offset(uint64_t sectionHeaderOffset);
    void processor_flag(uint32_t processorFlag);
    void header_size(uint32_t headerSize);
    void program_header_size(uint32_t programHeaderSize);
    void numberof_segments(uint32_t n);
    void sizeof_section_header(uint32_t sizeOfSectionHeaderEntries);
    void numberof_sections(uint32_t n);
    void section_name_table_idx(uint32_t sectionNameStringTableIdx);
    void identity(const std::string& identity);
    void identity(const identity_t& identity);
    void identity_class(ELF_CLASS i_class);
    void identity_data(ELF_DATA data);
    void identity_version(VERSION version);
    void identity_os_abi(OS_ABI osabi);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Header& rhs) const;
    bool operator!=(const Header& rhs) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

  private:
    //! Field which represent ElfXX_Ehdr->e_ident
    identity_t          identity_;

    //! Field which represent ElfXX_Ehdr->e_type
    E_TYPE  fileType_;

    //! Field which represent ElfXX_Ehdr->e_machine
    ARCH    machineType_;

    //! Field which represent ElfXX_Ehdr->e_version
    VERSION objectFileVersion_;

    //! Field which represent ElfXX_Ehdr->e_entry
    uint64_t            entryPoint_;

    //! Field which represent ElfXX_Ehdr->e_phoff
    uint64_t            programHeaderOffset_;

    //! Field which represent ElfXX_Ehdr->e_shoff
    uint64_t            sectionHeaderOffset_;

    //! Field which represent ElfXX_Ehdr->e_flags
    uint32_t            processorFlag_;

    //! Field which represent ElfXX_Ehdr->e_ehsize
    uint32_t            headerSize_;

    //! Field which represent ElfXX_Ehdr->e_phentsize
    uint32_t            programHeaderSize_;

    //! Field which represent ElfXX_Ehdr->e_phnum
    uint32_t            numberof_segments_;

    //! Field which represent ElfXX_Ehdr->e_shentsize
    uint32_t            sizeOfSectionHeaderEntries_;

    //! Field which represent ElfXX_Ehdr->e_shnum
    uint32_t            numberof_sections_;

    //! Field which represent ElfXX_Ehdr->e_shstrndx
    uint32_t            sectionNameStringTableIdx_;

};
}
}
#endif
