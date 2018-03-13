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
#ifndef LIEF_ELF_HASH_H_
#define LIEF_ELF_HASH_H_

#include "LIEF/visibility.h"
#include "LIEF/hash.hpp"
#include "LIEF/ELF.hpp"

namespace LIEF {
namespace ELF {

class LIEF_API Hash : public LIEF::Hash {
  public:
  static size_t hash(const Object& obj);

  public:
  using LIEF::Hash::Hash;
  using LIEF::Hash::visit;

  public:
  virtual void visit(const Binary& binary)                  override;
  virtual void visit(const Header& header)                  override;
  virtual void visit(const Section& section)                override;
  virtual void visit(const Segment& segment)                override;
  virtual void visit(const DynamicEntry& entry)             override;
  virtual void visit(const DynamicEntryArray& entry)        override;
  virtual void visit(const DynamicEntryLibrary& entry)      override;
  virtual void visit(const DynamicEntryRpath& entry)        override;
  virtual void visit(const DynamicEntryRunPath& entry)      override;
  virtual void visit(const DynamicSharedObject& entry)      override;
  virtual void visit(const DynamicEntryFlags& entry)        override;
  virtual void visit(const Symbol& symbol)                  override;
  virtual void visit(const Relocation& relocation)          override;
  virtual void visit(const SymbolVersion& sv)               override;
  virtual void visit(const SymbolVersionAux& sv)            override;
  virtual void visit(const SymbolVersionAuxRequirement& sv) override;
  virtual void visit(const SymbolVersionRequirement& svr)   override;
  virtual void visit(const SymbolVersionDefinition& svd)    override;
  virtual void visit(const Note& note)                      override;
  virtual void visit(const AndroidNote& note)               override;
  virtual void visit(const GnuHash& gnuhash)                override;
  virtual void visit(const SysvHash& sysvhash)              override;

  virtual ~Hash(void);
};

}
}

#endif
