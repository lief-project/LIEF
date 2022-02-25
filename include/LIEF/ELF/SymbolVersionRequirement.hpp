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
#ifndef LIEF_ELF_SYMBOL_VERSION_REQUIREMENTS_H_
#define LIEF_ELF_SYMBOL_VERSION_REQUIREMENTS_H_

#include <string>
#include <iostream>
#include <vector>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"

namespace LIEF {
namespace ELF {
class Parser;

namespace details {
struct Elf64_Verneed;
struct Elf32_Verneed;
}

//! Class which represents an entry in the ``DT_VERNEED`` or ``.gnu.version_r`` table
class LIEF_API SymbolVersionRequirement : public Object {
  friend class Parser;

  public:
  using aux_requirement_t        = std::vector<std::unique_ptr<SymbolVersionAuxRequirement>>;
  using it_aux_requirement       = ref_iterator<aux_requirement_t&, SymbolVersionAuxRequirement*>;
  using it_const_aux_requirement = const_ref_iterator<const aux_requirement_t&, const SymbolVersionAuxRequirement*>;

  SymbolVersionRequirement();
  SymbolVersionRequirement(const details::Elf64_Verneed& header);
  SymbolVersionRequirement(const details::Elf32_Verneed& header);
  virtual ~SymbolVersionRequirement();

  SymbolVersionRequirement& operator=(SymbolVersionRequirement other);
  SymbolVersionRequirement(const SymbolVersionRequirement& other);
  void swap(SymbolVersionRequirement& other);

  //! Version revision
  //!
  //! This field should always have the value ``1``. It will be changed
  //! if the versioning implementation has to be changed in an incompatible way.
  uint16_t version() const;

  //! Number of associated auxiliary entries
  uint32_t cnt() const;

  //! Auxiliary entries as an iterator over SymbolVersionAuxRequirement
  it_aux_requirement       auxiliary_symbols();
  it_const_aux_requirement auxiliary_symbols() const;

  //! Return the library name associated with this requirement (e.g. ``libc.so.6``)
  const std::string& name() const;

  void version(uint16_t version);
  void name(const std::string& name);

  //! Add a version auxiliary requirement to the existing list
  SymbolVersionAuxRequirement& add_aux_requirement(const SymbolVersionAuxRequirement& aux_requirement);

  void accept(Visitor& visitor) const override;

  bool operator==(const SymbolVersionRequirement& rhs) const;
  bool operator!=(const SymbolVersionRequirement& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const SymbolVersionRequirement& symr);

  private:
  aux_requirement_t aux_requirements_;
  uint16_t    version_ = 0;
  std::string name_;
};

}
}
#endif

