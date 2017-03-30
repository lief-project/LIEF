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
#ifndef LIEF_PE_RELOCATION_ENTRY_H_
#define LIEF_PE_RELOCATION_ENTRY_H_

#include <string>
#include <iostream>

#include "LIEF/Visitable.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class DLL_PUBLIC RelocationEntry : public Visitable {

  friend class Parser;
  friend class Builder;

  public:
    RelocationEntry(void);
    RelocationEntry(const RelocationEntry&);
    RelocationEntry& operator=(const RelocationEntry&);
    RelocationEntry(uint16_t data);
    RelocationEntry(uint16_t position, RELOCATIONS_BASE_TYPES type);
    virtual ~RelocationEntry(void);

    uint16_t data(void) const;
    uint16_t position(void) const;
    RELOCATIONS_BASE_TYPES  type(void) const;

    void data(uint16_t data);
    void position(uint16_t position);
    void type(RELOCATIONS_BASE_TYPES type);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const RelocationEntry& rhs) const;
    bool operator!=(const RelocationEntry& rhs) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const RelocationEntry& entry);

  private:
    uint16_t               position_;
    RELOCATIONS_BASE_TYPES type_;
};

}
}
#endif
