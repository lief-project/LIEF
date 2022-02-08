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
#ifndef LIEF_PE_RELOCATION_ENTRY_H_
#define LIEF_PE_RELOCATION_ENTRY_H_

#include <string>
#include <iostream>

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;
class Relocation;

//! Class which represents an entry of the PE relocation table
//!
//! It extends the LIEF::Relocation object to provide an uniform API across the file formats
class LIEF_API RelocationEntry : public LIEF::Relocation {

  friend class Parser;
  friend class Builder;
  friend class PE::Relocation;

  public:
  RelocationEntry();
  RelocationEntry(const RelocationEntry& other);
  RelocationEntry& operator=(RelocationEntry other);
  RelocationEntry(uint16_t data);
  RelocationEntry(uint16_t position, RELOCATIONS_BASE_TYPES type);
  virtual ~RelocationEntry();

  void swap(RelocationEntry& other);

  //! The address of the relocation
  uint64_t address() const override;

  void address(uint64_t address) override;

  //! The size of the relocatable pointer
  size_t size() const override;

  void size(size_t size) override;

  //! Raw data of the relocation:
  //! - The **high** 4 bits store the relocation type
  //! - The **low** 12 bits store the relocation offset
  uint16_t data() const;

  //! Offset relative to Relocation::virtual_address where the relocation occurs.
  uint16_t position() const;

  //! Type of the relocation
  RELOCATIONS_BASE_TYPES type() const;

  void data(uint16_t data);
  void position(uint16_t position);
  void type(RELOCATIONS_BASE_TYPES type);

  void accept(Visitor& visitor) const override;

  bool operator==(const RelocationEntry& rhs) const;
  bool operator!=(const RelocationEntry& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const RelocationEntry& entry);

  private:
  uint16_t               position_;
  RELOCATIONS_BASE_TYPES type_;
  PE::Relocation*        relocation_{nullptr}; // Used to compute some information
};

}
}
#endif
