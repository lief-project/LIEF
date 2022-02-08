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
#ifndef LIEF_PE_RICH_HEADER_H_
#define LIEF_PE_RICH_HEADER_H_
#include <array>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/iterators.hpp"

#include "LIEF/PE/RichEntry.hpp"

namespace LIEF {
namespace PE {

//! Class which represents the not-so-documented rich header
class LIEF_API RichHeader : public Object {
  public:

  using entries_t        = std::vector<RichEntry>;
  using it_entries       = ref_iterator<entries_t&>;
  using it_const_entries = const_ref_iterator<const entries_t&>;

  RichHeader();
  RichHeader(const RichHeader&);
  RichHeader& operator=(const RichHeader&);
  virtual ~RichHeader();

  //! Key used to encode the header (xor operation)
  uint32_t key() const;

  //! Return an iterator over the PE::RichEntry within the header
  it_entries entries();
  it_const_entries entries() const;

  void key(uint32_t key);

  //! Add a new PE::RichEntry
  void add_entry(const RichEntry& entry);

  //! Add a new entry given the id, build_id and count
  void add_entry(uint16_t id, uint16_t build_id, uint32_t count);

  void accept(Visitor& visitor) const override;

  bool operator==(const RichHeader& rhs) const;
  bool operator!=(const RichHeader& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const RichHeader& rich_header);

  private:
  uint32_t  key_ = 0;
  entries_t entries_;

};
}
}

#endif

