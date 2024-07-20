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
#ifndef LIEF_PE_RESOURCE_VAR_FILE_INFO_H
#define LIEF_PE_RESOURCE_VAR_FILE_INFO_H
#include <ostream>
#include <cstdint>
#include <vector>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

namespace LIEF {
namespace PE {

class ResourcesManager;
class ResourceVersion;
struct ResourcesParser;

//! This object describes information about languages supported by the application
//!
//! @see LIEF::PE::ResourceVersion
class LIEF_API ResourceVarFileInfo : public Object {

  friend class ResourcesManager;
  friend class ResourceVersion;
  friend struct ResourcesParser;

  public:
  ResourceVarFileInfo();
  ResourceVarFileInfo(uint16_t type, std::u16string key);
  ResourceVarFileInfo(const ResourceVarFileInfo&) = default;
  ResourceVarFileInfo& operator=(const ResourceVarFileInfo&) = default;
  ~ResourceVarFileInfo() override = default;

  //! The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type() const {
    return type_;
  }

  //! Signature of the structure:
  //! Must be the unicode string "VarFileInfo"
  const std::u16string& key() const {
    return key_;
  }

  //! List of languages that the application supports
  //!
  //! The **least** significant 16-bits  must contain a Microsoft language identifier,
  //! and the **most** significant 16-bits must contain the PE::CODE_PAGES
  //! Either **most** or **least** 16-bits can be zero, indicating that the file is language or code page independent.
  const std::vector<uint32_t>& translations() const {
    return translations_;
  }

  std::vector<uint32_t>& translations() {
    return translations_;
  }

  void type(uint16_t type) {
    type_ = type;
  }

  void key(std::u16string key) {
    key_ = std::move(key);
  }

  void key(const std::string& key);

  void translations(std::vector<uint32_t> translations) {
    translations_ = std::move(translations);
  }

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceVarFileInfo& entry);

  private:
  uint16_t  type_ = 0;
  std::u16string key_;
  std::vector<uint32_t> translations_;

};
}
}

#endif
