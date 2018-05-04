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
#include <iomanip>
#include <fstream>
#include <iterator>
#include <algorithm>
#include <functional>
#include <numeric>

#include "LIEF/exception.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/resources/ResourceDialog.hpp"

namespace LIEF {
namespace PE {

ResourceDialog::ResourceDialog(const ResourceDialog&) = default;
ResourceDialog& ResourceDialog::operator=(const ResourceDialog&) = default;
ResourceDialog::~ResourceDialog(void) = default;

ResourceDialog::ResourceDialog(void) :
  version_{0},
  signature_{0},
  help_id_{0},
  ext_style_{0},
  style_{0},
  x_{0},
  y_{0},
  cx_{0},
  cy_{0},
  menu_{},
  window_class_{},
  title_{},
  point_size_{0},
  weight_{0},
  italic_{false},
  charset_{0},
  typeface_{},
  items_{},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT}
{}


ResourceDialog::ResourceDialog(const pe_dialog_template_ext *header) :
  version_{header->version},
  signature_{header->signature},
  help_id_{header->help_id},
  ext_style_{header->ext_style},
  style_{header->style},
  x_{header->x},
  y_{header->y},
  cx_{header->cx},
  cy_{header->cy},
  menu_{},
  window_class_{},
  title_{},
  point_size_{0},
  weight_{0},
  italic_{false},
  charset_{0},
  typeface_{},
  items_{},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT}
{}


ResourceDialog::ResourceDialog(const pe_dialog_template *header) :
  version_{0},
  signature_{0},
  help_id_{0},
  ext_style_{header->ext_style},
  style_{header->style},
  x_{header->x},
  y_{header->y},
  cx_{header->cx},
  cy_{header->cy},
  menu_{},
  window_class_{},
  title_{},
  point_size_{0},
  weight_{0},
  italic_{false},
  charset_{0},
  typeface_{},
  items_{},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT}
{}


bool ResourceDialog::is_extended(void) const {
  return this->signature_ == 0xFFFF;
}

uint32_t ResourceDialog::extended_style(void) const {
  return this->ext_style_;
}

std::set<EXTENDED_WINDOW_STYLES> ResourceDialog::extended_style_list(void) const {
  std::set<EXTENDED_WINDOW_STYLES> ext_styles;
  std::copy_if(
      std::begin(extended_window_styles_array),
      std::end(extended_window_styles_array),
      std::inserter(ext_styles, std::begin(ext_styles)),
      std::bind(&ResourceDialog::has_extended_style, this, std::placeholders::_1));

  return ext_styles;

}

bool ResourceDialog::has_extended_style(EXTENDED_WINDOW_STYLES style) const {
  return (this->ext_style_ & static_cast<uint32_t>(style)) != 0;
}

uint32_t ResourceDialog::style(void) const {
  return this->style_;
}

std::set<WINDOW_STYLES> ResourceDialog::style_list(void) const {
  std::set<WINDOW_STYLES> styles;
  std::copy_if(
      std::begin(window_styles_array),
      std::end(window_styles_array),
      std::inserter(styles, std::begin(styles)),
      std::bind(&ResourceDialog::has_style, this, std::placeholders::_1));

  return styles;
}

bool ResourceDialog::has_style(WINDOW_STYLES style) const {
  return (this->style_ & static_cast<uint32_t>(style)) != 0;
}


std::set<DIALOG_BOX_STYLES> ResourceDialog::dialogbox_style_list(void) const {
  std::set<DIALOG_BOX_STYLES> styles;
  std::copy_if(
      std::begin(dialog_box_styles_array),
      std::end(dialog_box_styles_array),
      std::inserter(styles, std::begin(styles)),
      std::bind(&ResourceDialog::has_dialogbox_style, this, std::placeholders::_1));

  return styles;
}

bool ResourceDialog::has_dialogbox_style(DIALOG_BOX_STYLES style) const {
  return (this->style_ & static_cast<uint32_t>(style)) != 0;
}

int16_t ResourceDialog::x(void) const {
  return this->x_;
}

int16_t ResourceDialog::y(void) const {
  return this->y_;
}

int16_t ResourceDialog::cx(void) const {
  return this->cx_;
}

int16_t ResourceDialog::cy(void) const {
  return this->cy_;
}


it_const_dialog_items ResourceDialog::items(void) const {
  return this->items_;
}


RESOURCE_LANGS ResourceDialog::lang(void) const {
  return this->lang_;
}

RESOURCE_SUBLANGS ResourceDialog::sub_lang(void) const {
  return this->sublang_;
}

void ResourceDialog::lang(RESOURCE_LANGS lang) {
  this->lang_ = lang;
}

void ResourceDialog::sub_lang(RESOURCE_SUBLANGS sub_lang) {
  this->sublang_ = sub_lang;
}


// Extended API
// ============
uint16_t ResourceDialog::version(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->version_;
}

uint16_t ResourceDialog::signature(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->signature_;
}

uint32_t ResourceDialog::help_id(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->help_id_;
}


uint16_t ResourceDialog::weight(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->weight_;
}


uint8_t ResourceDialog::charset(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->charset_;
}


uint16_t ResourceDialog::point_size(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->point_size_;
}


bool ResourceDialog::is_italic(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->italic_;
}

const std::u16string& ResourceDialog::title(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }

  return this->title_;
}


const std::u16string& ResourceDialog::typeface(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }

  return this->typeface_;
}

void ResourceDialog::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceDialog::operator==(const ResourceDialog& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDialog::operator!=(const ResourceDialog& rhs) const {
  return not (*this == rhs);
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

