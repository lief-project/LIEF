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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_ARRAY_H_
#define LIEF_ELF_DYNAMIC_ENTRY_ARRAY_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {

//! Class that represent an Array in the dynamic table.
//! This entry is associated with constructors:
//! - ``DT_PREINIT_ARRAY``
//! - ``DT_INIT_ARRAY``
//! - ``DT_FINI_ARRAY``
//!
//! The underlying values are 64-bits integers to cover both:
//! ELF32 and ELF64 binaries.
class LIEF_API DynamicEntryArray : public DynamicEntry {
  public:
  using array_t = std::vector<uint64_t>;

  public:
  using DynamicEntry::DynamicEntry;

  DynamicEntryArray();
  DynamicEntryArray(DYNAMIC_TAGS tag, array_t array);

  DynamicEntryArray& operator=(const DynamicEntryArray&);
  DynamicEntryArray(const DynamicEntryArray&);

  //! Return the array values (list of pointer)
  array_t& array();

  const array_t& array() const;
  void array(const array_t& array);

  //! Insert the given function at ``pos``
  DynamicEntryArray& insert(size_t pos, uint64_t function);

  //! Append the given function
  DynamicEntryArray& append(uint64_t function);

  //! Remove the given function
  DynamicEntryArray& remove(uint64_t function);

  //! Number of function registred in this array
  size_t size() const;

  DynamicEntryArray& operator+=(uint64_t value);
  DynamicEntryArray& operator-=(uint64_t value);

  const uint64_t& operator[](size_t idx) const;
  uint64_t&       operator[](size_t idx);

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  virtual ~DynamicEntryArray();

  static bool classof(const DynamicEntry* entry);

  private:
  array_t array_;

};
}
}

#endif
