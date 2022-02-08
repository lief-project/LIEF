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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_RPATH_H_
#define LIEF_ELF_DYNAMIC_ENTRY_RPATH_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {

//! Class which represents a ``DT_RPATH`` entry. This attribute is
//! deprecated (cf. ``man ld``) in favour of ``DT_RUNPATH`` (See DynamicRunPath)
class LIEF_API DynamicEntryRpath : public DynamicEntry {

  public:
  static constexpr char delimiter = ':';
  using DynamicEntry::DynamicEntry;
  DynamicEntryRpath();

  DynamicEntryRpath(std::string rpath);

  //! Constructor from a list of paths
  DynamicEntryRpath(const std::vector<std::string>& paths);

  DynamicEntryRpath& operator=(const DynamicEntryRpath&);
  DynamicEntryRpath(const DynamicEntryRpath&);

  //! The actual rpath as a string
  const std::string& name() const;
  void name(const std::string& name);

  //! The actual rpath as a string
  const std::string& rpath() const;
  void rpath(const std::string& name);

  //! Paths as a list
  std::vector<std::string> paths() const;
  void paths(const std::vector<std::string>& paths);

  //! Insert a ``path`` at the given ``position``
  DynamicEntryRpath& insert(size_t pos, const std::string& path);

  //! Append the given ``path``
  DynamicEntryRpath& append(const std::string& path);

  //! Remove the given ``path``
  DynamicEntryRpath& remove(const std::string& path);

  DynamicEntryRpath& operator+=(const std::string& path);
  DynamicEntryRpath& operator-=(const std::string& path);

  static bool classof(const DynamicEntry* entry);

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  private:
  std::string rpath_;
};
}
}

#endif
