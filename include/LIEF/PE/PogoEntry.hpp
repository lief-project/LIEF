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
#ifndef LIEF_PE_POGO_ENTRY_H_
#define LIEF_PE_POGO_ENTRY_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

class Builder;
class Parser;

class LIEF_API PogoEntry : public Object {

  friend class Builder;
  friend class Parser;

  public:

  PogoEntry(void);
  PogoEntry(const PogoEntry&);
  PogoEntry(uint32_t start_rva, uint32_t size, const std::string& name);

  PogoEntry& operator=(const PogoEntry&);
  virtual ~PogoEntry(void);


  uint32_t start_rva() const;
  uint32_t size() const;
  const std::string& name() const;

  void start_rva(uint32_t start_rva);
  void size(uint32_t size);
  void name(const std::string&  name);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const PogoEntry& rhs) const;
  bool operator!=(const PogoEntry& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const PogoEntry& entry);


  protected:
    uint32_t start_rva_;
    uint32_t size_;
    std::string name_;
};

} // Namespace PE
} // Namespace LIEF

#endif
