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
#ifndef LIEF_PE_RELOCATION_H_
#define LIEF_PE_RELOCATION_H_
#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/type_traits.hpp"
#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class LIEF_API Relocation : public Object {

  friend class Parser;
  friend class Builder;

  public:
    Relocation(void);
    Relocation(const Relocation& other);
    Relocation& operator=(Relocation other);
    Relocation(const pe_base_relocation_block* header);
    virtual ~Relocation(void);

    void swap(Relocation& other);

    uint32_t virtual_address(void) const;
    uint32_t block_size(void) const;
    it_const_relocation_entries entries(void) const;
    it_relocation_entries entries(void);

    void virtual_address(uint32_t virtual_address);
    void block_size(uint32_t block_size);
    RelocationEntry& add_entry(const RelocationEntry& entry);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Relocation& rhs) const;
    bool operator!=(const Relocation& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& relocation);

  private:
    uint32_t             block_size_;
    uint32_t             virtual_address_;
    relocation_entries_t entries_;
};

}
}
#endif /* RELOCATION_H_ */
