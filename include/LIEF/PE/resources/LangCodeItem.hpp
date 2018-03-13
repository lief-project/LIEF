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
#ifndef LIEF_PE_RESOURCE_LANG_CODE_ITEM_H_
#define LIEF_PE_RESOURCE_LANG_CODE_ITEM_H_
#include <iostream>
#include <sstream>
#include <vector>
#include <map>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

class ResourcesManager;

//! @brief It's basically a map of key/value
//!
//! @see LIEF::PE::ResourceStringFileInfo
//!
//! see: https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms646992(v=vs.85).aspx
class LIEF_API LangCodeItem : public Object {

  friend class ResourcesManager;

  public:
  LangCodeItem(void);

  LangCodeItem(const LangCodeItem&);
  LangCodeItem& operator=(const LangCodeItem&);
  virtual ~LangCodeItem(void);

  //! @brief The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type(void) const;

  //! @brief A 8-digit hexadecimal number stored as an Unicode string.
  //! * The four most significant digits represent the language identifier.
  //! * The four least significant digits represent the code page for which the data is formatted.
  //!
  //! @see LangCodeItem::code_page, LangCodeItem::lang, LangCodeItem::sublang
  const std::u16string& key(void) const;

  //! @brief @link https://msdn.microsoft.com/en-us/library/windows/desktop/dd317756(v=vs.85).aspx Code page @endlink
  //! for which @link LangCodeItem::items items @endlink are defined
  CODE_PAGES code_page(void) const;

  //! @brief Lang for which @link LangCodeItem::items items @endlink are defined
  RESOURCE_LANGS lang(void) const;

  //! @brief Sublang for which @link LangCodeItem::items items @endlink are defined
  RESOURCE_SUBLANGS sublang(void) const;

  const std::map<std::u16string, std::u16string>& items(void) const;
  std::map<std::u16string, std::u16string>&       items(void);

  void type(uint16_t type);
  void key(const std::u16string& key);
  void key(const std::string& key);

  void code_page(CODE_PAGES code_page);
  void lang(RESOURCE_LANGS lang);
  void sublang(RESOURCE_SUBLANGS lang);

  void items(const std::map<std::u16string, std::u16string>& items);


  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LangCodeItem& rhs) const;
  bool operator!=(const LangCodeItem& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const LangCodeItem& item);

  private:
  uint16_t       type_;
  std::u16string key_;
  std::map<std::u16string, std::u16string> items_;

};




}
}


#endif
