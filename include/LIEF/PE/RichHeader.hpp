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
#ifndef LIEF_PE_RICH_HEADER_H_
#define LIEF_PE_RICH_HEADER_H_
#include <array>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/type_traits.hpp"

#include "LIEF/PE/RichEntry.hpp"

namespace LIEF {
namespace PE {

class LIEF_API RichHeader : public Object {
  public:

    RichHeader(void);
    RichHeader(const RichHeader&);
    RichHeader& operator=(const RichHeader&);
    virtual ~RichHeader(void);

    //! @brief Key used to encode the header (xor operation)
    uint32_t key(void) const;

    //! @brief Return an iterator on the PE::RichEntry within the header
    it_rich_entries entries(void);

    it_const_rich_entries entries(void) const;

    void key(uint32_t key);

    //! @brief Add a new PE::RichEntry
    void add_entry(const RichEntry& entry);
    void add_entry(uint16_t id, uint16_t build_id, uint32_t count);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const RichHeader& rhs) const;
    bool operator!=(const RichHeader& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const RichHeader& rich_header);

  private:
    uint32_t       key_;
    rich_entries_t entries_;

};
}
}

#endif

