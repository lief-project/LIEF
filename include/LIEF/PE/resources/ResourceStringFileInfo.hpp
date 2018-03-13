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
#ifndef LIEF_PE_RESOURCE_STRING_FILE_INFO_H_
#define LIEF_PE_RESOURCE_STRING_FILE_INFO_H_
#include <iostream>
#include <sstream>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"

#include "LIEF/PE/resources/LangCodeItem.hpp"

namespace LIEF {
namespace PE {

class ResourcesManager;
class ResourceVersion;

//! @brief Modelization of the ``StringFileInfo`` structure
//!
//! It contains version information that can be displayed for a particular language and code page.
//!
//! See: https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms646989(v=vs.85).aspx
class LIEF_API ResourceStringFileInfo : public Object {

  friend class ResourcesManager;
  friend class ResourceVersion;

  public:
  ResourceStringFileInfo(const ResourceStringFileInfo&);
  ResourceStringFileInfo& operator=(const ResourceStringFileInfo&);
  virtual ~ResourceStringFileInfo(void);

  //! @brief The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type(void) const;

  //! @brief Signature of the structure:
  //! Must be the unicode string "StringFileInfo"
  const std::u16string& key(void) const;

  //! @brief List of the LangCodeItem items.
  //!
  //! Each LangCodeItem::key indicates the appropriate
  //! language and code page for displaying the ``key: value`` of
  //! LangCodeItem::items
  const std::vector<LangCodeItem>& langcode_items(void) const;
  std::vector<LangCodeItem>&       langcode_items(void);

  void type(uint16_t type);

  void key(const std::u16string& key);
  void key(const std::string& key);
  void langcode_items(const std::vector<LangCodeItem>& items);


  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceStringFileInfo& rhs) const;
  bool operator!=(const ResourceStringFileInfo& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceStringFileInfo& string_file_info);

  private:
  ResourceStringFileInfo(void);

  uint16_t                  type_;
  std::u16string            key_;
  std::vector<LangCodeItem> childs_;


};




}
}


#endif
