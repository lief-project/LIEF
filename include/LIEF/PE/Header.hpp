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
#ifndef LIEF_PE_HEADER_H_
#define LIEF_PE_HEADER_H_
#include <array>
#include <set>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

namespace details {
struct pe_header;
}

//! Class that represents the PE header (which follows the DosHeader)
class LIEF_API Header : public Object {
  public:
  using signature_t = std::array<uint8_t, /* PE Magic */ 4>;
  Header();
  Header(const details::pe_header& header);
  virtual ~Header();

  Header& operator=(const Header&);
  Header(const Header&);

  //! Signature (or magic byte) of the header. It must be: ``PE\0\0``
  const signature_t& signature() const;

  //! The targeted machine architecture like ARM, x86, AMD64, ...
  MACHINE_TYPES machine() const;

  //! The number of sections in the binary.
  uint16_t numberof_sections() const;

  //! The low 32 bits of the number of seconds since
  //! January 1, 1970. Basically, it **indicates** when the file was created.
  uint32_t time_date_stamp() const;

  //! The offset of the **COFF** symbol table.
  //!
  //! This value should be zero for an image because COFF debugging information is deprecated.
  uint32_t pointerto_symbol_table() const;

  //! The number of entries in the symbol table. This data can be used to locate the string table
  //! which immediately follows the symbol table.
  //!
  //! This value should be zero for an image because COFF debugging information is deprecated.
  uint32_t numberof_symbols() const;

  //! Size of the OptionalHeader **AND** the data directories which follows this header.
  //!
  //! This value is equivalent to: ``sizeof(pe_optional_header) + NB_DATA_DIR * sizeof(data_directory)``
  //!
  //! This size **should** be either:
  //! * 0xE0 (224) for a PE32  (32 bits)
  //! * 0xF0 (240) for a PE32+ (64 bits)
  uint16_t sizeof_optional_header() const;

  //! Characteristics of the binary like whether it is a DLL or an executable
  HEADER_CHARACTERISTICS characteristics() const;

  //! Check if the given HEADER_CHARACTERISTICS is present
  bool has_characteristic(HEADER_CHARACTERISTICS c) const;

  //! The list of the HEADER_CHARACTERISTICS as an std::set
  std::set<HEADER_CHARACTERISTICS> characteristics_list() const;

  void machine(MACHINE_TYPES type);
  void numberof_sections(uint16_t nbOfSections);
  void time_date_stamp(uint32_t timestamp);
  void pointerto_symbol_table(uint32_t pointerToSymbol);
  void numberof_symbols(uint32_t nbOfSymbols);
  void sizeof_optional_header(uint16_t sizeOfOptionalHdr);
  void characteristics(HEADER_CHARACTERISTICS characteristics);
  void signature(const signature_t& sig);

  void add_characteristic(HEADER_CHARACTERISTICS c);
  void remove_characteristic(HEADER_CHARACTERISTICS c);

  void accept(Visitor& visitor) const override;

  bool operator==(const Header& rhs) const;
  bool operator!=(const Header& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& entry);

  private:
  signature_t   signature_;
  MACHINE_TYPES machine_;
  uint16_t numberOfSections_;
  uint32_t timeDateStamp_;
  uint32_t pointerToSymbolTable_;
  uint32_t numberOfSymbols_;
  uint16_t sizeOfOptionalHeader_;
  HEADER_CHARACTERISTICS characteristics_;

};
}
}

#endif
