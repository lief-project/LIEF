/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_PE_RESOURCE_STRING_FILE_INFO_H
#define LIEF_PE_RESOURCE_STRING_FILE_INFO_H
#include <ostream>
#include <vector>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"
#include "LIEF/PE/resources/LangCodeItem.hpp"

namespace LIEF {
namespace PE {

class ResourcesManager;
class ResourceVersion;
struct ResourcesParser;

//! Representation of the ``StringFileInfo`` structure
//!
//! It contains version information that can be displayed for a particular language and code page.
//!
//! See: https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
class LIEF_API ResourceStringFileInfo : public Object {

  friend class ResourcesManager;
  friend class ResourceVersion;
  friend struct ResourcesParser;

  public:
  ResourceStringFileInfo();
  ResourceStringFileInfo(uint16_t type, std::u16string key) :
    type_(type),
    key_(std::move(key))
  {}
  ResourceStringFileInfo(const ResourceStringFileInfo&) = default;
  ResourceStringFileInfo& operator=(const ResourceStringFileInfo&) = default;
  ~ResourceStringFileInfo() override = default;

  //! The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type() const {
    return type_;
  }

  //! Signature of the structure:
  //! Must be the unicode string "StringFileInfo"
  const std::u16string& key() const {
    return key_;
  }

  //! List of the LangCodeItem items.
  //!
  //! Each LangCodeItem::key indicates the appropriate
  //! language and code page for displaying the ``key: value`` of
  //! LangCodeItem::items
  const std::vector<LangCodeItem>& langcode_items() const {
    return childs_;
  }
  std::vector<LangCodeItem>& langcode_items() {
    return childs_;
  }

  void type(uint16_t type) {
    type_ = type;
  }

  void key(std::u16string key) {
    key_ = std::move(key);
  }
  void key(const std::string& key);

  void langcode_items(std::vector<LangCodeItem> items) {
    childs_ = std::move(items);
  }

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceStringFileInfo& string_file_info);

  private:
  uint16_t       type_ = 0;
  std::u16string key_;
  std::vector<LangCodeItem> childs_;


};




}
}


#endif
