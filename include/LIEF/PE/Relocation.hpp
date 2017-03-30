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

#include "LIEF/Visitable.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class DLL_PUBLIC Relocation : public Visitable {

  friend class Parser;
  friend class Builder;

  public:
    Relocation(void);
    Relocation(const Relocation& other);
    Relocation& operator=(const Relocation& other);
    Relocation(const pe_base_relocation_block* header);
    virtual ~Relocation(void);

    uint32_t virtual_address(void) const;
    uint32_t block_size(void) const;
    const std::vector<RelocationEntry>& entries(void) const;

    void virtual_address(uint32_t virtual_address);
    void block_size(uint32_t block_size);
    void add_entry(const RelocationEntry& entry);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Relocation& rhs) const;
    bool operator!=(const Relocation& rhs) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const Relocation& relocation);

  private:
    uint32_t                     block_size_;
    uint32_t                     virtual_address_;
    std::vector<RelocationEntry> entries_;
};

}
}
#endif /* RELOCATION_H_ */
