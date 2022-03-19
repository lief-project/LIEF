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
#ifndef LIEF_PE_DELAY_IMPORT_ENTRY_H
#define LIEF_PE_DELAY_IMPORT_ENTRY_H
#include <iostream>
#include <string>

#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/PE/enums.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {
class Parser;
class Builder;

//! Class that represents an entry (i.e. an import) in the delay import table
//! (DelayImport).
//!
//! It extends the LIEF::Symbol generic class that exposes the
//! LIEF::Symbol::name and LIEF::Symbol::value API
//!
//! The meaning of LIEF::Symbol::value for this PE object is the address (as an
//! RVA) in the IAT where the resolution should take place
class LIEF_API DelayImportEntry : public LIEF::Symbol {
  friend class Parser;
  friend class Builder;

 public:
  DelayImportEntry();
  DelayImportEntry(uint64_t data, PE_TYPE type);

  DelayImportEntry(const DelayImportEntry&);
  DelayImportEntry& operator=(const DelayImportEntry&);

  DelayImportEntry(DelayImportEntry&&);
  DelayImportEntry& operator=(DelayImportEntry&&);

  ~DelayImportEntry() override;

  //!``True`` if it is an import by ordinal
  bool is_ordinal() const;

  //! The ordinal value
  uint16_t ordinal() const;

  //! @see DelayImportEntry::data
  uint64_t hint_name_rva() const;

  //! Index into the Export::entries that is used to speed-up
  //! the symbol resolution.
  uint16_t hint() const;

  //! Value of the current entry in the Import Address Table.
  uint64_t iat_value() const;

  //! Raw value
  uint64_t data() const;

  void data(uint64_t data);

  void accept(Visitor& visitor) const override;

  bool operator==(const DelayImportEntry& rhs) const;
  bool operator!=(const DelayImportEntry& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const DelayImportEntry& entry);

 private:
  uint64_t data_ = 0;
  uint16_t hint_ = 0;
  uint64_t iat_offset_ = 0;
  uint64_t iat_value_ = 0;
  PE_TYPE type_ = PE_TYPE::PE32_PLUS;
};

}  // namespace PE
}  // namespace LIEF

#endif /* LIEF_PE_DELAY_IMPORT_ENTRY_H */
