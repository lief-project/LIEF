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
#ifndef LIEF_PE_RESOURCE_DIRECTORY_H_
#define LIEF_PE_RESOURCE_DIRECTORY_H_

#include <string>
#include <list>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/ResourceNode.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class LIEF_API ResourceDirectory : public ResourceNode {

  friend class Parser;
  friend class Builder;

  public:
    ResourceDirectory(void);
    ResourceDirectory(const pe_resource_directory_table* header);

    ResourceDirectory(const ResourceDirectory& other);
    ResourceDirectory& operator=(ResourceDirectory other);

    void swap(ResourceDirectory& other);

    virtual ~ResourceDirectory(void);

    virtual ResourceDirectory* clone(void) const override;

    //! @brief Resource flags. This field is reserved for future use.
    //! It is currently set to zero.
    uint32_t characteristics(void) const;

    //! @brief The time that the resource data was created by the
    //! resource compiler.
    uint32_t time_date_stamp(void) const;

    //! @brief The major version number, set by the user.
    uint16_t major_version(void) const;

    //! @brief The minor version number, set by the user.
    uint16_t minor_version(void) const;

    //! @brief The number of directory entries immediately
    //! following the table that use strings to identify Type,
    //! Name, or Language entries (depending on the level
    //! of the table).
    uint16_t numberof_name_entries(void) const;

    //! @brief The number of directory entries immediately
    //! following the Name entries that use numeric IDs for
    //! Type, Name, or Language entries.
    uint16_t numberof_id_entries(void) const;

    void characteristics(uint32_t characteristics);
    void time_date_stamp(uint32_t time_date_stamp);
    void major_version(uint16_t major_version);
    void minor_version(uint16_t minor_version);
    void numberof_name_entries(uint16_t numberof_name_entries);
    void numberof_id_entries(uint16_t numberof_id_entries);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const ResourceDirectory& rhs) const;
    bool operator!=(const ResourceDirectory& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceDirectory& directory);

  private:
    uint32_t characteristics_;
    uint32_t timeDateStamp_;
    uint16_t majorVersion_;
    uint16_t minorVersion_;
    uint16_t numberOfNameEntries_;
    uint16_t numberOfIDEntries_;

};
}
}
#endif /* RESOURCEDIRECTORY_H_ */
