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
#include <iomanip>
#include <fstream>
#include <iterator>
#include <algorithm>
#include <functional>
#include <numeric>
#include "logging.hpp"
#include "LIEF/exception.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"

#include "LIEF/PE/resources/ResourceDialog.hpp"

namespace LIEF {
namespace PE {

ResourceDialog::ResourceDialog(const ResourceDialog&) = default;
ResourceDialog& ResourceDialog::operator=(const ResourceDialog&) = default;
ResourceDialog::~ResourceDialog() = default;

ResourceDialog::ResourceDialog() :
  version_{0},
  signature_{0},
  help_id_{0},
  ext_style_{0},
  style_{0},
  x_{0},
  y_{0},
  cx_{0},
  cy_{0},
  point_size_{0},
  weight_{0},
  italic_{false},
  charset_{0},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT}
{}


ResourceDialog::ResourceDialog(const details::pe_dialog_template_ext& header) :
  version_{header.version},
  signature_{header.signature},
  help_id_{header.help_id},
  ext_style_{header.ext_style},
  style_{header.style},
  x_{header.x},
  y_{header.y},
  cx_{header.cx},
  cy_{header.cy},
  point_size_{0},
  weight_{0},
  italic_{false},
  charset_{0},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT}
{}


ResourceDialog::ResourceDialog(const details::pe_dialog_template& header) :
  version_{0},
  signature_{0},
  help_id_{0},
  ext_style_{header.ext_style},
  style_{header.style},
  x_{header.x},
  y_{header.y},
  cx_{header.cx},
  cy_{header.cy},
  point_size_{0},
  weight_{0},
  italic_{false},
  charset_{0},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT}
{}


bool ResourceDialog::is_extended() const {
  return signature_ == 0xFFFF;
}

uint32_t ResourceDialog::extended_style() const {
  return ext_style_;
}

std::set<EXTENDED_WINDOW_STYLES> ResourceDialog::extended_style_list() const {
  std::set<EXTENDED_WINDOW_STYLES> ext_styles;
  std::copy_if(
      std::begin(details::extended_window_styles_array),
      std::end(details::extended_window_styles_array),
      std::inserter(ext_styles, std::begin(ext_styles)),
      [this] (EXTENDED_WINDOW_STYLES f) { return has_extended_style(f); });

  return ext_styles;

}

bool ResourceDialog::has_extended_style(EXTENDED_WINDOW_STYLES style) const {
  return (ext_style_ & static_cast<uint32_t>(style)) != 0;
}

uint32_t ResourceDialog::style() const {
  return style_;
}

std::set<WINDOW_STYLES> ResourceDialog::style_list() const {
  std::set<WINDOW_STYLES> styles;
  std::copy_if(
      std::begin(details::window_styles_array),
      std::end(details::window_styles_array),
      std::inserter(styles, std::begin(styles)),
      [this] (WINDOW_STYLES f) { return has_style(f); });

  return styles;
}

bool ResourceDialog::has_style(WINDOW_STYLES style) const {
  return (style_ & static_cast<uint32_t>(style)) != 0;
}


std::set<DIALOG_BOX_STYLES> ResourceDialog::dialogbox_style_list() const {
  std::set<DIALOG_BOX_STYLES> styles;
  std::copy_if(
      std::begin(details::dialog_box_styles_array),
      std::end(details::dialog_box_styles_array),
      std::inserter(styles, std::begin(styles)),
      [this] (DIALOG_BOX_STYLES f) { return has_dialogbox_style(f); });

  return styles;
}

bool ResourceDialog::has_dialogbox_style(DIALOG_BOX_STYLES style) const {
  return (style_ & static_cast<uint32_t>(style)) != 0;
}

int16_t ResourceDialog::x() const {
  return x_;
}

int16_t ResourceDialog::y() const {
  return y_;
}

int16_t ResourceDialog::cx() const {
  return cx_;
}

int16_t ResourceDialog::cy() const {
  return cy_;
}


ResourceDialog::it_const_items ResourceDialog::items() const {
  return items_;
}


RESOURCE_LANGS ResourceDialog::lang() const {
  return lang_;
}

RESOURCE_SUBLANGS ResourceDialog::sub_lang() const {
  return sublang_;
}

void ResourceDialog::lang(RESOURCE_LANGS lang) {
  lang_ = lang;
}

void ResourceDialog::sub_lang(RESOURCE_SUBLANGS sub_lang) {
  sublang_ = sub_lang;
}


// Extended API
// ============
uint16_t ResourceDialog::version() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.dlgVer does not exist");
  }
  return version_;
}

uint16_t ResourceDialog::signature() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.signature does not exist");
  }
  return signature_;
}

uint32_t ResourceDialog::help_id() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.helpID does not exist");
  }
  return help_id_;
}


uint16_t ResourceDialog::weight() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.weight does not exist");
  }
  return weight_;
}


uint8_t ResourceDialog::charset() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.charset does not exist");
  }
  return charset_;
}


uint16_t ResourceDialog::point_size() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.pointsize does not exist");
  }
  return point_size_;
}


bool ResourceDialog::is_italic() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.italic does not exist");
  }
  return italic_;
}

const std::u16string& ResourceDialog::title() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.title does not exist");
  }

  return title_;
}


const std::u16string& ResourceDialog::typeface() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.typeface does not exist");
  }

  return typeface_;
}

void ResourceDialog::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceDialog::operator==(const ResourceDialog& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDialog::operator!=(const ResourceDialog& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceDialog& dialog) {

  const std::set<WINDOW_STYLES>& styles = dialog.style_list();
  std::string styles_str = std::accumulate(
     std::begin(styles),
     std::end(styles), std::string{},
     [] (const std::string& a, WINDOW_STYLES b) {
         return a.empty() ? to_string(b) : a + ", " + to_string(b);
     });


  const std::set<DIALOG_BOX_STYLES>& dialogbox_styles = dialog.dialogbox_style_list();
  std::string dialogbox_styles_str = std::accumulate(
     std::begin(dialogbox_styles),
     std::end(dialogbox_styles), std::string{},
     [] (const std::string& a, DIALOG_BOX_STYLES b) {
         return a.empty() ? to_string(b) : a + ", " + to_string(b);
     });


  const std::set<EXTENDED_WINDOW_STYLES>& ext_styles = dialog.extended_style_list();
  std::string ext_styles_str = std::accumulate(
     std::begin(ext_styles),
     std::end(ext_styles), std::string{},
     [] (const std::string& a, EXTENDED_WINDOW_STYLES b) {
         return a.empty() ? to_string(b) : a + ", " + to_string(b);
     });

  if (dialog.is_extended()) {
    os << "DIALOGEX ";
  } else {
    os << "DIALOG ";
  }
  os << std::dec << dialog.x() << ", " << dialog.y() << ", " << dialog.cx() << ", " << dialog.cy() << std::endl;
  os << "Version: "           << std::dec << dialog.version()      << std::endl;
  os << "Signature: "         << std::hex << dialog.signature()      << std::endl;
  os << "Styles: "            << styles_str            << std::endl;
  os << "Dialog box styles: " << dialogbox_styles_str  << std::endl;
  os << "Extended styles: "   << ext_styles_str        << std::endl;
  os << "Lang: "              << to_string(dialog.lang()) << " / " << to_string(dialog.sub_lang()) << std::endl;

  if (dialog.is_extended()) {
    os << "Title: \"" << u16tou8(dialog.title()) << "\"" << std::endl;
    os << "Font: \""
       << std::dec << dialog.point_size()
       << " " << u16tou8(dialog.typeface()) << "\""
       << ", " << std::boolalpha << dialog.is_italic()
       << ", " << std::dec << static_cast<uint32_t>(dialog.charset()) << std::endl;
  }

  os << "{" << std::endl;
  for (const ResourceDialogItem& item : dialog.items()) {
    os << "    " << item << std::endl;
  }

  os << "}" << std::endl;
  return os;
}



}
}

