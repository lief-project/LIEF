/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_PE_RESOURCES_PARSER_H
#define LIEF_PE_RESOURCES_PARSER_H
#include "LIEF/errors.hpp"
#include "LIEF/PE/resources/ResourceVersion.hpp"
namespace LIEF {
class BinaryStream;
namespace PE {
class ResourceVersion;
class LangCodeItem;
class ResourceData;

struct ResourcesParser {
  //! Parse the resource version structure described by:
  //!
  //! ```
  //! typedef struct {
  //!   WORD             wLength;
  //!   WORD             wValueLength;
  //!   WORD             wType;
  //!   WCHAR            szKey;
  //!   WORD             Padding1;
  //!   VS_FIXEDFILEINFO Value;
  //!   WORD             Padding2;
  //!   WORD             Children;
  //! } VS_VERSIONINFO;
  //! ```
  //! See: https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
  static result<ResourceVersion> parse_vs_versioninfo(BinaryStream& stream);

  static ok_error_t parse_version_info_child(ResourceVersion& version, BinaryStream& stream);

  static ok_error_t parse_var_file_info(ResourceVersion& version, BinaryStream& stream);
  static ok_error_t parse_string_file_info(ResourceVersion& version, BinaryStream& stream);
  static ok_error_t parse_string(LangCodeItem& lci, BinaryStream& stream);

  static ok_error_t parse_dialogs(std::vector<ResourceDialog>& dialogs,
                                  const ResourceData& node, BinaryStream& stream);

  static ok_error_t parse_ext_dialogs(std::vector<ResourceDialog>& dialogs,
                                      const ResourceData& node, BinaryStream& stream);

  static ok_error_t parse_tail_ext_dialog(ResourceDialog& dialog, BinaryStream& stream);
  static ok_error_t parse_ext_dialog_item(ResourceDialog& dialog, BinaryStream& stream);

  static ok_error_t parse_regular_dialogs(std::vector<ResourceDialog>& dialog,
                                          const ResourceData& node, BinaryStream& stream);
};

}
}
#endif
