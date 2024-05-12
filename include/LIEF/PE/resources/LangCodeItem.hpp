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
#ifndef LIEF_PE_RESOURCE_LANG_CODE_ITEM_H
#define LIEF_PE_RESOURCE_LANG_CODE_ITEM_H
#include <ostream>
#include <unordered_map>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class ResourcesManager;
struct ResourcesParser;

//! Class which represents the childs of the ResourceStringFileInfo
//!
//! @see: LIEF::PE::ResourceStringFileInfo
//! @see: https://docs.microsoft.com/en-us/windows/win32/menurc/stringtable
class LIEF_API LangCodeItem : public Object {

  friend class ResourcesManager;
  friend struct ResourcesParser;

  public:
  using items_t = std::unordered_map<std::u16string, std::u16string>;
  LangCodeItem();
  LangCodeItem(uint16_t type, std::u16string key) :
    type_(type),
    key_(std::move(key))
  {}

  LangCodeItem(const LangCodeItem&) = default;
  LangCodeItem& operator=(const LangCodeItem&) = default;
  ~LangCodeItem() override = default;

  //! The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type() const {
    return type_;
  }

  //! A 8-digit hexadecimal number stored as an Unicode string.
  //! * The four most significant digits represent the language identifier.
  //! * The four least significant digits represent the code page for which the data is formatted.
  //!
  //! @see LangCodeItem::code_page, LangCodeItem::lang, LangCodeItem::sublang
  const std::u16string& key() const {
    return key_;
  }

  //! [Code page](https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers)
  //! for which LangCodeItem::items are defined
  CODE_PAGES code_page() const;

  //! Lang for which LangCodeItem::items are defined
  uint32_t lang() const;

  //! Sublang for which LangCodeItem::items are defined
  uint32_t sublang() const;

  const items_t& items() const {
    return items_;
  }

  items_t& items() {
    return items_;
  }

  void type(uint16_t type) {
    type_ = type;
  }

  void key(const std::u16string& key) {
    key_ = key;
  }
  void key(const std::string& key);

  void code_page(CODE_PAGES code_page);
  void lang(uint32_t lang);
  void sublang(uint32_t lang);

  void items(const items_t& items);

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const LangCodeItem& item);

  private:
  uint16_t       type_ = 0;
  std::u16string key_;
  items_t        items_;
};




}
}


#endif
