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
#include "logging.hpp"
#include "PE/ResourcesParser.hpp"
#include "PE/Structures.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/resources/LangCodeItem.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"
#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"
#include "LIEF/PE/resources/ResourceDialog.hpp"
namespace LIEF {
namespace PE {
result<ResourceVersion> ResourcesParser::parse_vs_versioninfo(BinaryStream& stream) {
  stream.setpos(0);
  LIEF_DEBUG("Parsing VS_VERSIONINFO | Stream size: 0x{:x}", stream.size());

  ResourceVersion version;

  uint16_t wLength = 0;
  uint16_t wValueLength = 0;
  uint16_t wType = 0;
  std::u16string szKey;

  // wLength: Size of the current "struct"
  if (auto res = stream.read<uint16_t>()) {
    wLength = *res;
    LIEF_DEBUG("VS_VERSIONINFO.wLength: 0x{:x}", wLength);
  } else {
    LIEF_ERR("Can't read VS_VERSIONINFO.wLength");
    return make_error_code(lief_errors::parsing_error);
  }


  // wValueLength: Size of the fixed file info struct
  if (auto res = stream.read<uint16_t>()) {
    wValueLength = *res;
    LIEF_DEBUG("VS_VERSIONINFO.wValueLength: 0x{:x}", wValueLength);
  } else {
    LIEF_ERR("Can't read VS_VERSIONINFO.wValueLength");
    return make_error_code(lief_errors::parsing_error);
  }

  // wType:
  // The type of data in the version resource.
  // This member is 1 if the version resource contains text data and 0
  // if the version resource contains binary data.
  if (auto res = stream.read<uint16_t>()) {
    wType = *res;
    LIEF_DEBUG("VS_VERSIONINFO.wType: 0x{:x}", wType);
    if (wType != 0 && wType != 1) {
      LIEF_WARN("VS_VERSIONINFO.wType should be 1 or 0 but it is {}", wType);
    }
  } else {
    LIEF_ERR("Can't read VS_VERSIONINFO.wType");
    return make_error_code(lief_errors::parsing_error);
  }

  // szKey: The Unicode string L"VS_VERSION_INFO".
  if (auto res = stream.read_u16string()) {
    szKey = *res;
    std::string u8szKey = u16tou8(szKey);
    LIEF_DEBUG("VS_VERSIONINFO.szKey: {}", u8szKey);
    if (u8szKey != "VS_VERSION_INFO") {
      LIEF_WARN("VS_VERSIONINFO.szKey should be equal to 'VS_VERSION_INFO' but is {}", u8szKey);
    }
  } else {
    LIEF_ERR("Can't read VS_VERSIONINFO.szKey");
    return make_error_code(lief_errors::parsing_error);
  }

  // VS_VERSION_INFO.Padding1
  stream.align(sizeof(uint32_t));

  if (wValueLength > 0) {
    if (wValueLength == sizeof(details::pe_resource_fixed_file_info)) {
      // VS_FIXEDFILEINFO - https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
      if (auto res = stream.peek<details::pe_resource_fixed_file_info>()) {
        const auto VS_FIXEDFILEINFO = *res;
        if (VS_FIXEDFILEINFO.signature == 0xFEEF04BD) {
          version.fixed_file_info_ = std::make_unique<ResourceFixedFileInfo>(VS_FIXEDFILEINFO);
        } else {
          LIEF_WARN("Bad magic value for VS_FIXEDFILEINFO");
        }
      } else {
        LIEF_WARN("Can't read VS_VERSION_INFO.value");
      }
    } else {
      LIEF_WARN("The VS_VERSION_INFO.value contains an unknown structure");
    }
    stream.increment_pos(wValueLength);
  }

  // VS_VERSION_INFO.Padding2
  stream.align(sizeof(uint32_t));

  version.type_ = wType;
  version.key_  = std::move(szKey);

  LIEF_DEBUG("Reading VS_VERSION_INFO.children[0] @0x{:x}", stream.pos());
  if (!stream.can_read<uint16_t>()) {
    return version;
  }

  const uint16_t child_1_len = *stream.peek<uint16_t>();
  LIEF_DEBUG("VS_VERSION_INFO.children[0]: 0x{:x} bytes @0x{:x}", child_1_len, stream.pos());
  std::vector<uint8_t> child_1_data;
  if (stream.read_data(child_1_data, child_1_len)) {
    if (auto span_stream = SpanStream::from_vector(child_1_data)) {
      if (!parse_version_info_child(version, *span_stream)) {
        LIEF_ERR("Error while parsing VS_VERSION_INFO.children[0]");
      }
    }
  } else {
    LIEF_WARN("Can't read VS_VERSION_INFO.children[0]");
    return version;
  }

  stream.align(sizeof(uint32_t));

  LIEF_DEBUG("Reading VS_VERSION_INFO.children[1] @0x{:x}", stream.pos());
  if (!stream.can_read<uint16_t>()) {
    return version;
  }

  const uint16_t child_2_len = *stream.peek<uint16_t>();

  LIEF_DEBUG("VS_VERSION_INFO.children[1]: 0x{:x} bytes @0x{:x}", child_2_len, stream.pos());
  std::vector<uint8_t> child_2_data;
  if (stream.read_data(child_2_data, child_2_len)) {
    if (auto span_stream = SpanStream::from_vector(child_2_data)) {
      if (!parse_version_info_child(version, *span_stream)) {
        LIEF_ERR("Error while parsing VS_VERSION_INFO.children[1]");
      }
    }
  } else {
    LIEF_WARN("Can't read VS_VERSION_INFO.children[1]");
    return version;
  }

  return version;
}

ok_error_t ResourcesParser::parse_version_info_child(ResourceVersion& version, BinaryStream& stream) {
  /*  Both StringFileInfo & VarFileInfo share the following header:
   *  WORD        wLength;
   *  WORD        wValueLength;
   *  WORD        wType;
   *  WCHAR       szKey;
   *  WORD        Padding;
   */
  uint16_t wLength = 0;
  uint16_t wValueLength = 0;
  uint16_t wType = 0;
  std::u16string szKey;

  // wLength:
  // The length, in bytes, of the entire VarFileInfo/StringFileInfo block,
  // including all structures indicated by the Children member.
  if (auto res = stream.read<uint16_t>()) {
    wLength = *res;
    LIEF_DEBUG("Child.wLength: 0x{:x}", wLength);
  } else {
    LIEF_ERR("Can't read Child.wLength");
    return make_error_code(lief_errors::parsing_error);
  }

  // wValueLength: This member is always equal to zero.
  if (auto res = stream.read<uint16_t>()) {
    wValueLength = *res;
    LIEF_DEBUG("Child.wValueLength: 0x{:x}", wValueLength);
    if (wValueLength != 0) {
      LIEF_WARN("Child.wValueLength should be 0 instead of 0x{:x}", wValueLength);
    }
  } else {
    LIEF_ERR("Can't read Child.wValueLength");
    return make_error_code(lief_errors::parsing_error);
  }

  // wType: The type of data in the version resource.
  // This member is 1 if the version resource contains text data and
  // 0 if the version resource contains binary data.
  if (auto res = stream.read<uint16_t>()) {
    wType = *res;
    LIEF_DEBUG("Child.wType: 0x{:x}", wType);
    if (wType != 0 && wType != 1) {
      LIEF_WARN("Child.wType should be 0 or 1 instead of {}", wType);
    }
  } else {
    LIEF_ERR("Can't read Child.wType");
    return make_error_code(lief_errors::parsing_error);
  }

  // szKey: The Unicode string L"VarFileInfo" or L"StringFileInfo".
  if (auto res = stream.read_u16string()) {
    stream.align(sizeof(uint32_t));
    szKey = *res;
    std::string u8szKey = u16tou8(szKey);
    if (u8szKey == "VarFileInfo") {
      version.var_file_info_ = std::make_unique<ResourceVarFileInfo>(wType, szKey);
      if (!parse_var_file_info(version, stream)) {
        LIEF_WARN("Failed to parse VarFileInfo");
      }
    }
    else if (u8szKey == "StringFileInfo") {
      version.string_file_info_ = std::make_unique<ResourceStringFileInfo>(wType, szKey);
      if (!parse_string_file_info(version, stream)) {
        LIEF_WARN("Failed to parse StringFileInfo");
      }
    } else {
      LIEF_WARN("Child.szKey is neither VarFileInfo/StringFileInfo: '{}'", u8szKey);
      return make_error_code(lief_errors::parsing_error);
    }
    return ok();
  } else {
    LIEF_ERR("Can't read Child.szKey");
    return make_error_code(lief_errors::parsing_error);
  }
  return ok();
}


ok_error_t ResourcesParser::parse_var_file_info(ResourceVersion& version, BinaryStream& stream) {
   /*  https://docs.microsoft.com/en-us/windows/win32/menurc/varfileinfo
    * typedef struct {
    *   WORD  wLength;
    *   WORD  wValueLength;
    *   WORD  wType;
    *   WCHAR szKey;
    *   WORD  Padding;
    *   DWORD Value;
    * } Var;
    */
  while (stream) {
    uint16_t wLength = 0;
    uint16_t wValueLength = 0;
    uint16_t wType = 0;
    std::u16string szKey;

    if (auto res = stream.read<uint16_t>()) {
      wLength = *res;
      LIEF_DEBUG("Var.wLength: 0x{:x}", wLength);
    } else {
      LIEF_ERR("Can't read VarFileInfo.wLength");
    }

    if (auto res = stream.read<uint16_t>()) {
      wValueLength = *res;
      LIEF_DEBUG("Var.wValueLength: 0x{:x}", wValueLength);
    } else {
      LIEF_ERR("Can't read StringVarFileInfoTable.wValueLength");
    }

    if (auto res = stream.read<uint16_t>()) {
      wType = *res;
      LIEF_DEBUG("Var.wType: 0x{:x}", wType);
      if (wType != 0 && wType != 1) {
        LIEF_WARN("Var.wType should be 0 or 1 instead of {}", wType);
      }
    } else {
      LIEF_ERR("Can't read VarFileInfo.wType");
    }

    if (auto res = stream.read_u16string()) {
      szKey = *res;
      std::string u8szKey = u16tou8(szKey);
      LIEF_DEBUG("Var.szKey: {}", u8szKey);
      if (u8szKey != "Translation") {
        LIEF_WARN("Var.szKey should be 'Translation' instead of '{}'", u8szKey);
      }
      stream.align(sizeof(uint32_t));
      const size_t nb_items = wValueLength / sizeof(uint32_t);
      for (size_t i = 0; i < nb_items; ++i) {
        uint32_t val = 0;
        if (auto res = stream.read<uint32_t>()) {
          val = *res;
          LIEF_DEBUG("Var.Value[{}]: 0x{:x}", i, val);
          version.var_file_info_->translations_.push_back(val);
        } else {
          LIEF_WARN("Can't read Var.Value[{}]", i);
          break;
        }
      }
    } else {
      LIEF_ERR("Can't read VarFileInfo.szKey");
      return make_error_code(lief_errors::parsing_error);
    }
  }
  return ok();
}

ok_error_t ResourcesParser::parse_string_file_info(ResourceVersion& version, BinaryStream& stream) {
  /*
   * https://docs.microsoft.com/en-us/windows/win32/menurc/stringtable
   *
   * typedef struct {
   *   WORD   wLength;
   *   WORD   wValueLength;
   *   WORD   wType;
   *   WCHAR  szKey;
   *   WORD   Padding;
   *   String Children;
   * } StringTable;
   */
  while (stream) {
    uint16_t wLength = 0;
    uint16_t wValueLength = 0;
    uint16_t wType = 0;
    std::u16string szKey;

    const size_t pos = stream.pos();

    if (auto res = stream.read<uint16_t>()) {
      wLength = *res;
      LIEF_DEBUG("StringTable.wLength: 0x{:x}", wLength);
      if (wLength == 0) {
        LIEF_WARN("StringTable.wLength should not be null");
        break;
      }
    } else {
      LIEF_ERR("Can't read StringTable.wLength");
    }

    const size_t end_offset = pos + wLength;

    if (auto res = stream.read<uint16_t>()) {
      wValueLength = *res;
      LIEF_DEBUG("StringTable.wValueLength: 0x{:x}", wValueLength);
    } else {
      LIEF_ERR("Can't read StringTable.wValueLength");
    }

    if (auto res = stream.read<uint16_t>()) {
      wType = *res;
      if (wType != 0 && wType != 1) {
        LIEF_WARN("StringTable.wType should be 0 or 1 instead of {}", wType);
      }
      LIEF_DEBUG("StringTable.wType: 0x{:x}", wType);
    } else {
      LIEF_ERR("Can't read StringTable.wType");
    }

    // An 8-digit hexadecimal number stored as a Unicode string.
    // The four most significant digits represent the language identifier.
    // The four least significant digits represent the code page for which
    // the data is formatted. Each Microsoft Standard Language identifier
    // contains two parts: the low-order 10 bits specify the major
    // language, and the high-order 6 bits specify the sublanguage.
    // For a table of valid identifiers see .
    if (auto res = stream.read_u16string()) {
      szKey = *res;
      std::string u8szKey = u16tou8(szKey);
      LIEF_DEBUG("StringTable.szKey: {}", u8szKey);
      if (szKey.size() != 8) {
        LIEF_ERR("StringTable.szKey should be 8-wchars length");
        return make_error_code(lief_errors::parsing_error);
      }

      const std::string& chunk_1 = u16tou8(szKey.substr(0, 4));
      const std::string& chunk_2 = u16tou8(szKey.substr(4, 8));
      uint64_t lang_id = 0;
      uint64_t code_page = 0;
      if (is_hex_number(chunk_1)) {
        lang_id = std::stoul(chunk_1, nullptr, 16);
      } else {
        LIEF_WARN("Invalid hex-string for Lang ID: '{}'", chunk_1);
      }

      if (is_hex_number(chunk_2)) {
        code_page = std::stoul(chunk_2, nullptr, 16);
      } else {
        LIEF_WARN("Invalid hex-string for Code page: '{}'", chunk_2);
      }

      LIEF_DEBUG("Lang ID:   {}", lang_id);
      LIEF_DEBUG("Code page: 0x{:x}", code_page);

      LangCodeItem lang{wType, szKey};
      stream.align(sizeof(uint32_t));
      if (parse_string(lang, stream)) {
        version.string_file_info_->childs_.push_back(std::move(lang));
      } else {
        LIEF_WARN("StringTable.String parsed with error");
      }
    } else {
      LIEF_ERR("Can't read StringTable.szKey");
      return make_error_code(lief_errors::parsing_error);
    }
    stream.setpos(end_offset);
  }
  return ok();
}


ok_error_t ResourcesParser::parse_string(LangCodeItem& lci, BinaryStream& stream) {
  /* https://docs.microsoft.com/en-us/windows/win32/menurc/string-str
   * typedef struct {
   *   WORD  wLength;
   *   WORD  wValueLength; // The size, in words, of the Value member.
   *   WORD  wType;
   *   WCHAR szKey;
   *   WORD  Padding;
   *   WORD  Value;
   * } String;
   */
  uint16_t wLength = 0;
  uint16_t wValueLength = 0;
  uint16_t wType = 0;
  std::u16string szKey;
  std::u16string value;
  while (stream) {
    stream.align(sizeof(uint32_t));
    const size_t pos = stream.pos();
    if (auto res = stream.read<uint16_t>()) {
      wLength = *res;
      LIEF_DEBUG("String.wLength: 0x{:x}", wLength);
      if (wLength == 0) {
        LIEF_WARN("String.wLength should not be null.");
        break;
      }
    } else {
      LIEF_ERR("Can't read String.wLength");
    }

    const size_t end_offset = pos + wLength;

    if (auto res = stream.read<uint16_t>()) {
      wValueLength = *res;
      LIEF_DEBUG("String.wValueLength: 0x{:x}", wValueLength);
    } else {
      LIEF_ERR("Can't read String.wValueLength");
    }

    if (auto res = stream.read<uint16_t>()) {
      wType = *res;
      if (wType != 0 && wType != 1) {
        LIEF_WARN("String.wType should be 0 or 1 instead of {}", wType);
      }
      LIEF_DEBUG("String.wType: {}", wType);
    } else {
      LIEF_ERR("Can't read String.wType");
    }
    LIEF_DEBUG("String.szKey @0x{:x}", stream.pos());
    /*
     * Read the Key
     */
    if (auto res = stream.read_u16string()) {
      szKey = *res;
      std::string u8szKey = u16tou8(szKey);
      stream.align(sizeof(uint32_t));
      LIEF_DEBUG("String.Key: {}", u8szKey);
      /*
       * Read the value
       */
      if (wValueLength > 0) {
        LIEF_DEBUG("String.Value @0x{:x}", stream.pos());
        if (auto res = stream.read_u16string()) {
          if (res->size() + /* null char */ 1 != wValueLength) {
            LIEF_INFO("String.Value.size() is different from wValueLength ({} / {})",
                      wValueLength, res->size() + 1);
          }
          value = res->c_str(); // To remove trailling \0
          std::string u8value = u16tou8(value);
          LIEF_DEBUG("{}: {}", u8szKey, u8value);
          lci.items_.emplace(szKey, value);
          stream.align(sizeof(uint32_t));
        }
      } else {

        lci.items_.emplace(szKey, std::u16string());
      }
    } else {
      LIEF_ERR("Can't read String.szKey");
      return make_error_code(lief_errors::parsing_error);
    }
    stream.setpos(end_offset);
  }
  return ok();
}


ok_error_t ResourcesParser::parse_dialogs(std::vector<ResourceDialog>& dialogs,
                                          const ResourceData& node, BinaryStream& stream) {
  // Parse Dialogs as described in
  // - https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgtemplate
  // - https://docs.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
  // The given `stream` can point to both DLGTEMPLATEEX / DLGTEMPLATE so we need first
  // to determine the kind of the dialog

  // Try first DLGTEMPLATEEX
  if (auto dlgVer = stream.peek<uint16_t>()) {
    if (auto signature = stream.peek<uint16_t>(sizeof(uint16_t))) {
      if (*signature == 0xFFFF) {
        return parse_ext_dialogs(dialogs, node, stream);
      }
    }
  }
  return parse_regular_dialogs(dialogs, node, stream);
}


ok_error_t ResourcesParser::parse_ext_dialogs(std::vector<ResourceDialog>& dialogs,
                                              const ResourceData& node, BinaryStream& stream) {
  using sz_Or_Ord = uint16_t;

  ResourceDialog new_dialog;
  sz_Or_Ord menu = 0;
  sz_Or_Ord windowClass = 0;
  std::u16string title;
  size_t cDlgItems = 0;

  if (auto res = stream.read<details::pe_dialog_template_ext>()) {
    new_dialog = *res;
    cDlgItems = res->nbof_items;
  } else {
    LIEF_WARN("Can't parse DLGTEMPLATEEX");
    return make_error_code(lief_errors::read_error);
  }

  new_dialog.lang(ResourcesManager::lang_from_id(node.id()));
  new_dialog.sub_lang(ResourcesManager::sublang_from_id(node.id()));

  if (auto res = stream.read<uint16_t>()) {
    menu = *res;
    LIEF_DEBUG("DLGTEMPLATEEX.menu: 0x{:x}", menu);
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.menu");
    return make_error_code(lief_errors::read_error);
  }

  switch(menu) {
    case 0x0000:
      {
        LIEF_DEBUG("Dialog does not have a menu");
        break;
      }

    case 0xFFFF:
      {
        // if the first element is 0xFFFF, the array has one additional element
        // that specifies the ordinal value of a menu resource in an executable file [...]"
        uint16_t menu_ordinal = 0;
        if (auto res = stream.read<uint16_t>()) {
          menu_ordinal = *res;
          LIEF_DEBUG("DLGTEMPLATEEX.menu.ordinal: 0x{:x}", menu_ordinal);
        } else {
          LIEF_INFO("Can't read DLGTEMPLATEEX.menu.ordinal");
          return make_error_code(lief_errors::read_error);
        }
        break;
      }

    default:
      {
        // If the first element has any other value, the system treats the array as a
        // null-terminated Unicode string that specifies the name of a menu resource
        // in an executable file [...]
        std::u16string menu_name;
        if (auto res = stream.read_u16string()) {
          menu_name = *res;
          LIEF_DEBUG("DLGTEMPLATEEX.menu.name: {}", u16tou8(menu_name));
        } else {
          LIEF_INFO("Can't read DLGTEMPLATEEX.menu.name");
          return make_error_code(lief_errors::read_error);
        }
      }
  }

  stream.align(sizeof(uint16_t));

  if (auto res = stream.read<uint16_t>()) {
    windowClass = *res;
    LIEF_DEBUG("DLGTEMPLATEEX.windowClass: 0x{:x}", windowClass);
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.windowClass");
    return make_error_code(lief_errors::read_error);
  }

  switch(windowClass) {
    case 0x0000:
      {
        LIEF_DEBUG("Windows class uses a predefined dialog box");
        break;
      }

    case 0xFFFF:
      {
        uint16_t windowClass_ordinal = 0;
        if (auto res = stream.read<uint16_t>()) {
          windowClass_ordinal = *res;
          LIEF_DEBUG("DLGTEMPLATEEX.windowClass.ordinal: 0x{:x}", windowClass_ordinal);
        } else {
          LIEF_INFO("Can't read DLGTEMPLATEEX.windowClass.ordinal");
          return make_error_code(lief_errors::read_error);
        }
        break;
      }

    default:
      {
        std::u16string windowClass_name;
        if (auto res = stream.read_u16string()) {
          windowClass_name = *res;
          LIEF_DEBUG("DLGTEMPLATEEX.windowClass.name: {}", u16tou8(windowClass_name));
        } else {
          LIEF_INFO("Can't read DLGTEMPLATEEX.windowClass.name");
          return make_error_code(lief_errors::read_error);
        }
      }
  }

  stream.align(sizeof(uint16_t));

  if (auto res = stream.read_u16string()) {
    title = *res;
    LIEF_DEBUG("DLGTEMPLATEEX.title: {}", u16tou8(title));
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.title");
    return make_error_code(lief_errors::read_error);
  }

  new_dialog.title_ = title;

  if (!parse_tail_ext_dialog(new_dialog, stream)) {
    LIEF_INFO("Can't parse last fields of DLGTEMPLATEEX");
    return make_error_code(lief_errors::read_error);
  }

  for (size_t i = 0; i < cDlgItems; ++i) {
    LIEF_DEBUG("parsing DLGTEMPLATEEX.item[{}] at 0x{:04x}", i, stream.pos());
    if (!parse_ext_dialog_item(new_dialog, stream)) {
      LIEF_INFO("Error while parsing DLGTEMPLATEEX.item[{}]", i);
      break;
    }
    LIEF_DEBUG("[Done]: DLGTEMPLATEEX.item[{}]\n", i);
  }
  dialogs.push_back(std::move(new_dialog));
  return ok();
}


ok_error_t ResourcesParser::parse_tail_ext_dialog(ResourceDialog& dialog, BinaryStream& stream)
{
  const std::set<DIALOG_BOX_STYLES>& dialogbox_styles = dialog.dialogbox_style_list();
  // [...] This member is present only if the style member specifies DS_SETFONT or DS_SHELLFONT. [...]
  const bool has_ext_members = dialogbox_styles.count(DIALOG_BOX_STYLES::DS_SHELLFONT) > 0 ||
                               dialogbox_styles.count(DIALOG_BOX_STYLES::DS_SETFONT) > 0;
  if (!has_ext_members) {
    return ok();
  }
  uint16_t pointsize = 0;
  uint16_t weight = 0;
  uint8_t italic = 0;
  uint8_t charset = 0;
  std::u16string typeface;

  if (auto res = stream.read<uint16_t>()) {
    pointsize = *res;
    dialog.point_size_ = pointsize;
    LIEF_DEBUG("DLGTEMPLATEEX.pointsize: {}", pointsize);
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.pointsize");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream.read<uint16_t>()) {
    weight = *res;
    dialog.weight_ = weight;
    LIEF_DEBUG("DLGTEMPLATEEX.weight: {}", weight);
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.weight");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream.read<uint8_t>()) {
    dialog.italic_ = static_cast<bool>(*res);
    LIEF_DEBUG("DLGTEMPLATEEX.italic: {}", italic);
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.italic");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream.read<uint8_t>()) {
    charset = *res;
    dialog.charset_ = charset;
    LIEF_DEBUG("DLGTEMPLATEEX.charset: {}", charset);
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.charset");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream.read_u16string()) {
    typeface = *res;
    dialog.typeface_ = typeface;
    LIEF_DEBUG("DLGTEMPLATEEX.typeface: {}", u16tou8(typeface));
  } else {
    LIEF_INFO("Can't read DLGTEMPLATEEX.typeface");
    return make_error_code(lief_errors::read_error);
  }
  return ok();
}

ok_error_t ResourcesParser::parse_ext_dialog_item(ResourceDialog& dialog, BinaryStream& stream) {
  using sz_Or_Ord = uint16_t;

  // See: https://docs.microsoft.com/en-us/windows/win32/dlgbox/dlgitemtemplateex
  stream.align(sizeof(uint32_t));

  ResourceDialogItem dialog_item;
  if (!dialog.is_extended()) {
    if (auto res = stream.read<details::pe_dialog_item_template>()) {
      dialog.items_.emplace_back(*res);
      return ok();
    } else {
      LIEF_INFO("Can't read DLGITEMTEMPLATE");
      return make_error_code(lief_errors::read_error);
    }
  }
  // Extended dialog
  if (auto res = stream.read<details::pe_dialog_item_template_ext>()) {
    dialog_item = *res;
  } else {
    LIEF_INFO("Can't read DLGITEMTEMPLATEEX");
    return make_error_code(lief_errors::read_error);
  }

  sz_Or_Ord windowClass = 0;
  sz_Or_Ord title = 0;
  uint16_t extraCount = 0;

  stream.align(sizeof(uint16_t));
  /* Windows Class */ {
    if (auto res = stream.read<uint16_t>()) {
      windowClass = *res;
      LIEF_DEBUG("DLGITEMTEMPLATEEX.windowClass: 0x{:x}", windowClass);
    } else {
      LIEF_INFO("Can't read DLGITEMTEMPLATEEX.windowClass");
      return make_error_code(lief_errors::read_error);
    }

    if (windowClass == 0xFFFF) {
      uint16_t windowClass_ordinal = 0;
      if (auto res = stream.read<uint16_t>()) {
        windowClass_ordinal = *res;
        LIEF_DEBUG("DLGITEMTEMPLATEEX.windowClass.ordinal: 0x{:x}", windowClass_ordinal);
      } else {
        LIEF_INFO("Can't read DLGITEMTEMPLATEEX.windowClass.ordinal");
        return make_error_code(lief_errors::read_error);
      }

    } else {
      stream.decrement_pos(sizeof(uint16_t));
      std::u16string windowClass_name;
      if (auto res = stream.read_u16string()) {
        windowClass_name = *res;
        dialog_item.window_class_ = windowClass_name;
        LIEF_DEBUG("DLGITEMTEMPLATEEX.windowClass.name: {}", u16tou8(windowClass_name));
      } else {
        LIEF_INFO("Can't read DLGTEMPLATEEX.windowClass.name");
        return make_error_code(lief_errors::read_error);
      }
    }
    stream.align(sizeof(uint32_t));
  }

  /* Title */ {
    if (auto res = stream.read<uint16_t>()) {
      title = *res;
      LIEF_DEBUG("DLGITEMTEMPLATEEX.title: 0x{:x}", title);
    } else {
      LIEF_INFO("Can't read DLGITEMTEMPLATEEX.title");
      return make_error_code(lief_errors::read_error);
    }

    if (title == 0xFFFF) {
      uint16_t title_ordinal = 0;
      if (auto res = stream.read<uint16_t>()) {
        title_ordinal = *res;
        LIEF_DEBUG("DLGITEMTEMPLATEEX.title.ordinal: 0x{:x}", title_ordinal);
      } else {
        LIEF_INFO("Can't read DLGITEMTEMPLATEEX.title.ordinal");
        return make_error_code(lief_errors::read_error);
      }
    } else {
      stream.decrement_pos(sizeof(uint16_t));
      std::u16string title_name;
      if (auto res = stream.read_u16string()) {
        title_name = *res;
        dialog_item.title_ = title_name;
        LIEF_DEBUG("DLGITEMTEMPLATEEX.title.name: {}", u16tou8(title_name));
      } else {
        LIEF_INFO("Can't read DLGTEMPLATEEX.title");
        return make_error_code(lief_errors::read_error);
      }
    }
  }

  /* extraCount */ {
    if (auto res = stream.read<uint16_t>()) {
      extraCount = *res;
      dialog_item.extra_count_ = extraCount;
      LIEF_DEBUG("DLGITEMTEMPLATEEX.extraCount: 0x{:x}", extraCount);
      stream.increment_pos(extraCount);
    } else {
      LIEF_INFO("Can't read DLGITEMTEMPLATEEX.extraCount");
      return make_error_code(lief_errors::read_error);
    }
  }
  dialog.items_.push_back(std::move(dialog_item));
  return ok();
}

ok_error_t ResourcesParser::parse_regular_dialogs(std::vector<ResourceDialog>&,
                                                  const ResourceData&, BinaryStream&) {
  LIEF_INFO("Parsing regular dialogs is not implemented");
  return make_error_code(lief_errors::not_implemented);
}

}
}
