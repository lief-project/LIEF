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
#ifndef LIEF_PE_DOS_HEADER_H_
#define LIEF_PE_DOS_HEADER_H_
#include <array>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

class LIEF_API DosHeader : public Object {
  public:
    using reserved_t  = std::array<uint16_t, 4>;
    using reserved2_t = std::array<uint16_t, 10>;

    DosHeader(const pe_dos_header* header);
    DosHeader(void);
    DosHeader(const DosHeader&);
    DosHeader& operator=(const DosHeader&);
    virtual ~DosHeader(void);

    uint16_t    magic(void) const;
    uint16_t    used_bytes_in_the_last_page(void) const;
    uint16_t    file_size_in_pages(void) const;
    uint16_t    numberof_relocation(void) const;
    uint16_t    header_size_in_paragraphs(void) const;
    uint16_t    minimum_extra_paragraphs(void) const;
    uint16_t    maximum_extra_paragraphs(void) const;
    uint16_t    initial_relative_ss(void) const;
    uint16_t    initial_sp(void) const;
    uint16_t    checksum(void) const;
    uint16_t    initial_ip(void) const;
    uint16_t    initial_relative_cs(void) const;
    uint16_t    addressof_relocation_table(void) const;
    uint16_t    overlay_number(void) const;
    reserved_t  reserved(void) const;
    uint16_t    oem_id(void) const;
    uint16_t    oem_info(void) const;
    reserved2_t reserved2(void) const;
    uint32_t    addressof_new_exeheader(void) const;

    void magic(uint16_t magic);
    void used_bytes_in_the_last_page(uint16_t usedBytesInTheLastPage);
    void file_size_in_pages(uint16_t fileSizeInPages);
    void numberof_relocation(uint16_t numberOfRelocation);
    void header_size_in_paragraphs(uint16_t headerSizeInParagraphs);
    void minimum_extra_paragraphs(uint16_t minimumExtraParagraphs);
    void maximum_extra_paragraphs(uint16_t maximumExtraParagraphs);
    void initial_relative_ss(uint16_t initialRelativeSS);
    void initial_sp(uint16_t initialSP);
    void checksum(uint16_t checksum);
    void initial_ip(uint16_t initialIP);
    void initial_relative_cs(uint16_t initialRelativeCS);
    void addressof_relocation_table(uint16_t addressOfRelocationTable);
    void overlay_number(uint16_t overlayNumber);
    void reserved(const reserved_t& reserved);
    void oem_id(uint16_t oEMid);
    void oem_info(uint16_t oEMinfo);
    void reserved2(const reserved2_t& reserved2);
    void addressof_new_exeheader(uint32_t addressOfNewExeHeader);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const DosHeader& rhs) const;
    bool operator!=(const DosHeader& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const DosHeader& entry);

  private:
    uint16_t    magic_;
    uint16_t    usedBytesInTheLastPage_;
    uint16_t    fileSizeInPages_;
    uint16_t    numberOfRelocation_;
    uint16_t    headerSizeInParagraphs_;
    uint16_t    minimumExtraParagraphs_;
    uint16_t    maximumExtraParagraphs_;
    uint16_t    initialRelativeSS_;
    uint16_t    initialSP_;
    uint16_t    checksum_;
    uint16_t    initialIP_;
    uint16_t    initialRelativeCS_;
    uint16_t    addressOfRelocationTable_;
    uint16_t    overlayNumber_;
    reserved_t  reserved_;
    uint16_t    oEMid_;
    uint16_t    oEMinfo_;
    reserved2_t reserved2_;
    uint32_t    addressOfNewExeHeader_;
};
}
}

#endif

