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
#ifndef LIEF_ELF_SYMBOL_VERSION_DEFINITION_H_
#define LIEF_ELF_SYMBOL_VERSION_DEFINITION_H_
#include <iostream>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"

#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {

class Parser;

namespace details {
struct Elf64_Verdef;
struct Elf32_Verdef;
}

//! Class which represents an entry defined in ``DT_VERDEF`` or ``.gnu.version_d``
class LIEF_API SymbolVersionDefinition : public Object {
  friend class Parser;
  public:
  using version_aux_t        = std::vector<std::unique_ptr<SymbolVersionAux>>;
  using it_version_aux       = ref_iterator<version_aux_t&, SymbolVersionAux*>;
  using it_const_version_aux = const_ref_iterator<const version_aux_t&, const SymbolVersionAux*>;

  SymbolVersionDefinition();
  SymbolVersionDefinition(const details::Elf64_Verdef& header);
  SymbolVersionDefinition(const details::Elf32_Verdef& header);
  virtual ~SymbolVersionDefinition();

  SymbolVersionDefinition& operator=(SymbolVersionDefinition other);
  SymbolVersionDefinition(const SymbolVersionDefinition& other);
  void swap(SymbolVersionDefinition& other);

  //! Version revision
  //!
  //! This field should always have the value ``1``. It will be changed
  //! if the versioning implementation has to be changed in an incompatible way.
  uint16_t version() const;

  //! Version information
  uint16_t flags() const;

  //! Version index
  //!
  //! Numeric value used as an index in the LIEF::ELF::SymbolVersion table
  uint16_t ndx() const;

  //! Hash value of the symbol's name (using ELF hash function)
  uint32_t hash() const;

  //! SymbolVersionAux entries
  it_version_aux       symbols_aux();
  it_const_version_aux symbols_aux() const;

  void version(uint16_t version);
  void flags(uint16_t flags);
  void hash(uint32_t hash);

  void accept(Visitor& visitor) const override;

  bool operator==(const SymbolVersionDefinition& rhs) const;
  bool operator!=(const SymbolVersionDefinition& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const SymbolVersionDefinition& sym);

  private:
  uint16_t version_ = 1;
  uint16_t flags_ = 0;
  uint16_t ndx_  = 0;
  uint32_t hash_ = 0;
  version_aux_t symbol_version_aux_;
};
}
}
#endif

