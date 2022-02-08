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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_H_
#define LIEF_ELF_DYNAMIC_ENTRY_H_

#include <string>
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {
namespace details {
struct Elf64_Dyn;
struct Elf32_Dyn;
}

//! Class which represents an entry in the dynamic table
//! These entries are located in the ``.dynamic`` section or the ``PT_DYNAMIC`` segment
class LIEF_API DynamicEntry : public Object {
  public:

  DynamicEntry(const details::Elf64_Dyn& header);
  DynamicEntry(const details::Elf32_Dyn& header);
  DynamicEntry();
  DynamicEntry(DYNAMIC_TAGS tag, uint64_t value);

  DynamicEntry& operator=(const DynamicEntry&);
  DynamicEntry(const DynamicEntry&);
  virtual ~DynamicEntry();

  //! Tag of the current entry. The most common tags are:
  //! DT_NEEDED, DT_INIT, ...
  DYNAMIC_TAGS tag() const;

  //! Return the entry's value
  //!
  //! The meaning of the value strongly depends on the tag.
  //! It can be an offset, an index, a flag, ...
  uint64_t value() const;

  void tag(DYNAMIC_TAGS tag);
  void value(uint64_t value);

  void accept(Visitor& visitor) const override;

  virtual std::ostream& print(std::ostream& os) const;

  bool operator==(const DynamicEntry& rhs) const;
  bool operator!=(const DynamicEntry& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const DynamicEntry& entry);

  protected:
  DYNAMIC_TAGS tag_;
  uint64_t     value_;
};
}
}
#endif
