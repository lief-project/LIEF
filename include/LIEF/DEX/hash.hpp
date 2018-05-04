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
#ifndef LIEF_DEX_HASH_H_
#define LIEF_DEX_HASH_H_

#include "LIEF/visibility.h"
#include "LIEF/hash.hpp"
#include "LIEF/DEX.hpp"

namespace LIEF {
namespace DEX {

class LIEF_API Hash : public LIEF::Hash {
  public:
  static size_t hash(const Object& obj);

  public:
  using LIEF::Hash::Hash;
  using LIEF::Hash::visit;

  public:
  virtual void visit(const File& file)          override;
  virtual void visit(const Header& header)      override;
  virtual void visit(const Class& cls)          override;
  virtual void visit(const Method& method)      override;
  virtual void visit(const CodeInfo& code_info) override;
  virtual void visit(const Type& type)          override;
  virtual void visit(const Prototype& type)     override;
  virtual void visit(const MapItem& item)       override;
  virtual void visit(const MapList& list)       override;

  virtual ~Hash(void);
};

}
}

#endif
