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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_FLAGS_H_
#define LIEF_ELF_DYNAMIC_ENTRY_FLAGS_H_

#include <set>
#include <ostream>

#include "LIEF/visibility.h"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {

class LIEF_API DynamicEntryFlags : public DynamicEntry {

  public:
  using flags_list_t = std::set<uint32_t>;

  public:
  using DynamicEntry::DynamicEntry;
  DynamicEntryFlags();

  DynamicEntryFlags& operator=(const DynamicEntryFlags&);
  DynamicEntryFlags(const DynamicEntryFlags&);

  //! If the current entry has the given DYNAMIC_FLAGS
  bool has(DYNAMIC_FLAGS f) const;

  //! If the current entry has the given DYNAMIC_FLAGS_1
  bool has(DYNAMIC_FLAGS_1 f) const;

  //! Return flags as a list of integers
  flags_list_t flags() const;

  //! Add the given DYNAMIC_FLAGS
  void add(DYNAMIC_FLAGS f);

  //! Add the given DYNAMIC_FLAGS_1
  void add(DYNAMIC_FLAGS_1 f);

  //! Remove the given DYNAMIC_FLAGS
  void remove(DYNAMIC_FLAGS f);

  //! Remove the given DYNAMIC_FLAGS_1
  void remove(DYNAMIC_FLAGS_1 f);

  DynamicEntryFlags& operator+=(DYNAMIC_FLAGS f);
  DynamicEntryFlags& operator+=(DYNAMIC_FLAGS_1 f);

  DynamicEntryFlags& operator-=(DYNAMIC_FLAGS f);
  DynamicEntryFlags& operator-=(DYNAMIC_FLAGS_1 f);

  //! Method so that the ``visitor`` can visit us
  void accept(Visitor& visitor) const override;

  static bool classof(const DynamicEntry* entry);

  std::ostream& print(std::ostream& os) const override;
};
}
}

#endif
