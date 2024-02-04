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
#ifndef LIEF_PE_RESOURCE_VERSION_H
#define LIEF_PE_RESOURCE_VERSION_H
#include <ostream>
#include <sstream>
#include <memory>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

namespace LIEF {
namespace PE {
class ResourceFixedFileInfo;
class ResourceStringFileInfo;
class ResourceVarFileInfo;

class ResourcesManager;
struct ResourcesParser;

//! Representation of the data associated with the ``RT_VERSION`` entry
//!
//! See: ``VS_VERSIONINFO`` - https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
class LIEF_API ResourceVersion : public Object {
  friend class ResourcesManager;
  friend struct ResourcesParser;

  public:
  ResourceVersion(const ResourceVersion&);
  ResourceVersion& operator=(const ResourceVersion&);
  ~ResourceVersion() override;

  //! The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type() const;

  //! Signature of the structure:
  //! Must be the unicode string "VS_VERSION_INFO"
  const std::u16string& key() const;

  //! ``true`` if the version contains a ResourceFixedFileInfo
  bool has_fixed_file_info() const;

  //! ``true`` if the version contains a ResourceStringFileInfo
  bool has_string_file_info() const;

  //! ``true`` if the version contains a ResourceVarFileInfo
  bool has_var_file_info() const;

  //! Object that describes various information about the application's version.
  //! This is an optional information and if it is not present, it returns a nullptr
  const ResourceFixedFileInfo* fixed_file_info() const;
  ResourceFixedFileInfo*       fixed_file_info();

  //! Object that describes various information about the application's version.
  //! The underlying structure is basically a dictionary (key/value)
  //!
  //! This structure is not always present and if not, it returns a nullptr
  const ResourceStringFileInfo* string_file_info() const;
  ResourceStringFileInfo*       string_file_info();

  //! Object that describes information about languages supported by the application
  //! This structure is not always present and if not, it returns a nullptr
  const ResourceVarFileInfo* var_file_info() const;
  ResourceVarFileInfo*       var_file_info();

  void type(uint16_t type);

  void key(std::u16string key) {
    key_ = std::move(key);
  }
  void key(const std::string& key);

  void fixed_file_info(const ResourceFixedFileInfo& fixed_file_info);
  void remove_fixed_file_info();

  void string_file_info(const ResourceStringFileInfo& string_file_info);
  void remove_string_file_info();

  void var_file_info(const ResourceVarFileInfo& var_file_info);
  void remove_var_file_info();

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceVersion& version);

  private:
  ResourceVersion();

  uint16_t       type_;
  std::u16string key_;

  // Optional structures
  std::unique_ptr<ResourceFixedFileInfo>  fixed_file_info_;
  std::unique_ptr<ResourceStringFileInfo> string_file_info_;
  std::unique_ptr<ResourceVarFileInfo>    var_file_info_;
};




}
}


#endif
