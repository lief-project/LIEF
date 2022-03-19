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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_LIBRARY_H_
#define LIEF_ELF_DYNAMIC_ENTRY_LIBRARY_H_

#include <ostream>
#include <string>

#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {

//! Class which represents a ``DT_NEEDED`` entry in the dynamic table.
//!
//! This kind of entry is usually used to create library dependency.
class LIEF_API DynamicEntryLibrary : public DynamicEntry {
 public:
  using DynamicEntry::DynamicEntry;

  DynamicEntryLibrary();
  DynamicEntryLibrary(std::string name);

  DynamicEntryLibrary& operator=(const DynamicEntryLibrary&);
  DynamicEntryLibrary(const DynamicEntryLibrary&);

  //! Return the library associated with this entry (e.g. ``libc.so.6``)
  const std::string& name() const;
  void name(const std::string& name);

  static bool classof(const DynamicEntry* entry);

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

 private:
  std::string libname_;
};
}  // namespace ELF
}  // namespace LIEF

#endif
