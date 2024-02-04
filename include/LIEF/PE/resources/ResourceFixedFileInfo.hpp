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
#ifndef LIEF_PE_RESOURCE_FIXED_FILE_INFO_H
#define LIEF_PE_RESOURCE_FIXED_FILE_INFO_H
#include <ostream>
#include <sstream>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

namespace details {
struct pe_resource_fixed_file_info;
}

//! Representation of [VS_FIXEDFILEINFO](https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo)
//! Structure
class LIEF_API ResourceFixedFileInfo : public Object {

  public:
  ResourceFixedFileInfo();
  ResourceFixedFileInfo(const details::pe_resource_fixed_file_info& header);

  ResourceFixedFileInfo(const ResourceFixedFileInfo&);
  ResourceFixedFileInfo& operator=(const ResourceFixedFileInfo&);
  ~ResourceFixedFileInfo() override;

  //! Must be set to ``0xFEEF04BD``
  uint32_t signature() const;

  //! The binary version number of this structure.
  //!
  //! The high-order word of this member contains the major version number,
  //! and the low-order word contains the minor version number.
  uint32_t struct_version() const;

  //! The **most** significant 32 bits of the file's binary version number.
  //!
  //! This member is used with ResourceFixedFileInfo::file_version_LS to form a 64-bits
  //! value used for numeric comparisons.
  uint32_t file_version_MS() const;

  //! The **least** significant 32 bits of the file's binary version number.
  //!
  //! This member is used with ResourceFixedFileInfo::file_version_MS to form a 64-bits value used for numeric comparisons.
  uint32_t file_version_LS() const;

  //! The **most** significant 32 bits of the product with which this file was distributed
  //!
  //! This member is used with ResourceFixedFileInfo::product_version_LS to form a 64-bits value used for numeric comparisons.
  uint32_t product_version_MS() const;

  //! The **least** significant 32 bits of the product with which this file was distributed
  //!
  //! This member is used with ResourceFixedFileInfo::product_version_MS to form a 64-bits value used for numeric comparisons.
  uint32_t product_version_LS() const;

  //! Contains a bitmask that specifies the valid bits in ResourceFixedFileInfo::file_flags.
  //!
  //! A bit is valid only if it was defined when the file was created.
  uint32_t file_flags_mask() const;

  //! Contains a bitmask that specifies the Boolean attributes of the file
  //! (PE::FIXED_VERSION_FILE_FLAGS)
  uint32_t file_flags() const;

  //! The operating system for which this file was designed (PE::FIXED_VERSION_OS).
  FIXED_VERSION_OS file_os() const;

  //! The general type of file (PE::FIXED_VERSION_FILE_TYPES)
  FIXED_VERSION_FILE_TYPES file_type() const;

  //! The function of the file (PE::FIXED_VERSION_FILE_SUB_TYPES)
  FIXED_VERSION_FILE_SUB_TYPES file_subtype() const;

  //! The **most** significant 32 bits of the file's 64-bit binary creation date and time stamp.
  uint32_t file_date_MS() const;

  //! The **least** significant 32 bits of the file's 64-bit binary creation date and time stamp.
  uint32_t file_date_LS() const;

  void signature(uint32_t signature);
  void struct_version(uint32_t struct_version);
  void file_version_MS(uint32_t file_version_MS);
  void file_version_LS(uint32_t file_version_LS);
  void product_version_MS(uint32_t product_version_MS);
  void product_version_LS(uint32_t product_version_LS);
  void file_flags_mask(uint32_t file_flags_mask);
  void file_flags(uint32_t file_flags);
  void file_os(FIXED_VERSION_OS file_os);
  void file_type(FIXED_VERSION_FILE_TYPES file_type);
  void file_subtype(FIXED_VERSION_FILE_SUB_TYPES file_subtype);
  void file_date_MS(uint32_t file_date_MS);
  void file_date_LS(uint32_t file_date_LS);

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceFixedFileInfo& fixed_info);

  private:
  uint32_t                     signature_;
  uint32_t                     struct_version_;
  uint32_t                     file_version_MS_;
  uint32_t                     file_version_LS_;
  uint32_t                     product_version_MS_;
  uint32_t                     product_version_LS_;
  uint32_t                     file_flags_mask_;
  uint32_t                     file_flags_;
  FIXED_VERSION_OS             file_os_;
  FIXED_VERSION_FILE_TYPES     file_type_;
  FIXED_VERSION_FILE_SUB_TYPES file_subtype_;
  uint32_t                     file_date_MS_;
  uint32_t                     file_date_LS_;


};




}
}


#endif
