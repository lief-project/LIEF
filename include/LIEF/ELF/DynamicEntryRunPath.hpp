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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_RUNPATH_H_
#define LIEF_ELF_DYNAMIC_ENTRY_RUNPATH_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {

//! Class that represents a ``DT_RUNPATH`` wich is used by the loader
//! to resolve libraries (DynamicEntryLibrary).
class LIEF_API DynamicEntryRunPath : public DynamicEntry {

  public:
  static constexpr char delimiter = ':';
  using DynamicEntry::DynamicEntry;

  DynamicEntryRunPath();

  //! Constructor from (run)path
  DynamicEntryRunPath(std::string runpath);

  //! Constructor from a list of paths
  DynamicEntryRunPath(const std::vector<std::string>& paths);

  DynamicEntryRunPath& operator=(const DynamicEntryRunPath&);
  DynamicEntryRunPath(const DynamicEntryRunPath&);

  //! Runpath raw value
  const std::string& name() const;
  void name(const std::string& name);

  //! Runpath raw value
  const std::string& runpath() const;
  void runpath(const std::string& runpath);

  //! Paths as a list
  std::vector<std::string> paths() const;
  void paths(const std::vector<std::string>& paths);

  //! Insert a ``path`` at the given ``position``
  DynamicEntryRunPath& insert(size_t pos, const std::string& path);

  //! Append the given ``path``
  DynamicEntryRunPath& append(const std::string& path);

  //! Remove the given ``path``
  DynamicEntryRunPath& remove(const std::string& path);

  DynamicEntryRunPath& operator+=(const std::string& path);
  DynamicEntryRunPath& operator-=(const std::string& path);

  void accept(Visitor& visitor) const override;

  static bool classof(const DynamicEntry* entry);

  std::ostream& print(std::ostream& os) const override;

  private:
  std::string runpath_;
};
}
}
#endif
