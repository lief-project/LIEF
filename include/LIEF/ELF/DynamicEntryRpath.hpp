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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_RPATH_H_
#define LIEF_ELF_DYNAMIC_ENTRY_RPATH_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"


namespace LIEF {
namespace ELF {
class LIEF_API DynamicEntryRpath : public DynamicEntry {

  public:
    static constexpr char delimiter = ':';
    using DynamicEntry::DynamicEntry;
    DynamicEntryRpath(void);

    DynamicEntryRpath(const std::string& name);

    //! @brief Constructor from a list of paths
    DynamicEntryRpath(const std::vector<std::string>& paths);

    DynamicEntryRpath& operator=(const DynamicEntryRpath&);
    DynamicEntryRpath(const DynamicEntryRpath&);

    const std::string& name(void) const;
    void name(const std::string& name);

    const std::string& rpath(void) const;
    void rpath(const std::string& name);

    //! @brief Paths as a list
    std::vector<std::string> paths(void) const;
    void paths(const std::vector<std::string>& paths);

    //! @brief Insert a ``path`` at the given ``position``
    DynamicEntryRpath& insert(size_t pos, const std::string path);

    //! @brief Append the given ``path``
    DynamicEntryRpath& append(const std::string& path);

    //! @brief Remove the given ``path``
    DynamicEntryRpath& remove(const std::string& path);

    DynamicEntryRpath& operator+=(const std::string& path);
    DynamicEntryRpath& operator-=(const std::string& path);

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    std::string rpath_;
};
}
}

#endif
