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
#ifndef LIEF_PE_RESOURCE_VERSION_H_
#define LIEF_PE_RESOURCE_VERSION_H_
#include <iostream>
#include <sstream>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"

#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"

namespace LIEF {
namespace PE {

class ResourcesManager;

//! @brief Modelization of the data associated with the ``RT_VERSION`` entry
//!
//! See: ``VS_VERSIONINFO`` - https://msdn.microsoft.com/en-us/library/windows/desktop/ms647001(v=vs.85).aspx
class LIEF_API ResourceVersion : public Object {
  friend class ResourcesManager;

  public:
  ResourceVersion(const ResourceVersion&);
  ResourceVersion& operator=(const ResourceVersion&);
  virtual ~ResourceVersion(void);

  //! @brief The type of data in the version resource
  //! * ``1`` if it contains text data
  //! * ``0`` if it contains binary data
  uint16_t type(void) const;

  //! @brief Signature of the structure:
  //! Must be the unicode string "VS_VERSION_INFO"
  const std::u16string& key(void) const;

  //! @brief ``true`` if the version contains a ResourceFixedFileInfo
  bool has_fixed_file_info(void) const;

  //! @brief ``true`` if the version contains a ResourceStringFileInfo
  bool has_string_file_info(void) const;

  //! @brief ``true`` if the version contains a ResourceVarFileInfo
  bool has_var_file_info(void) const;

  //! @brief Object that describes various information about the application's version
  const ResourceFixedFileInfo& fixed_file_info(void) const;
  ResourceFixedFileInfo&       fixed_file_info(void);

  //! @brief Object that describes various information about the application's version.
  //! The underlying structure is basically a dictionary (key/value)
  const ResourceStringFileInfo& string_file_info(void) const;
  ResourceStringFileInfo&       string_file_info(void);

  //! @brief Object that describes information about languages supported by the application
  const ResourceVarFileInfo& var_file_info(void) const;
  ResourceVarFileInfo&       var_file_info(void);

  void type(uint16_t type);

  void key(const std::u16string& key);
  void key(const std::string& key);

  void fixed_file_info(const ResourceFixedFileInfo& fixed_file_info);
  void remove_fixed_file_info(void);

  void string_file_info(const ResourceStringFileInfo& string_file_info);
  void remove_string_file_info(void);

  void var_file_info(const ResourceVarFileInfo& var_file_info);
  void remove_var_file_info(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceVersion& rhs) const;
  bool operator!=(const ResourceVersion& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceVersion& version);

  private:
  ResourceVersion(void);

  uint16_t       type_;
  std::u16string key_;

  // Optional structures
  bool                   has_fixed_file_info_;
  ResourceFixedFileInfo  fixed_file_info_;

  bool                   has_string_file_info_;
  ResourceStringFileInfo string_file_info_;

  bool                   has_var_file_info_;
  ResourceVarFileInfo    var_file_info_;



};




}
}


#endif
