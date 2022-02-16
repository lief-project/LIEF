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

#include "LIEF/PE/resources/ResourceDialogItem.hpp"

namespace LIEF {
namespace PE {

ResourceDialogItem::ResourceDialogItem(const ResourceDialogItem&) = default;
ResourceDialogItem& ResourceDialogItem::operator=(const ResourceDialogItem&) = default;
ResourceDialogItem::~ResourceDialogItem() = default;

ResourceDialogItem::ResourceDialogItem() = default;

ResourceDialogItem::ResourceDialogItem(const details::pe_dialog_item_template_ext& header) :
  is_extended_{true},
  help_id_{header.help_id},
  ext_style_{header.ext_style},
  style_{header.style},
  id_{header.id},
  x_{header.x},
  y_{header.y},
  cx_{header.cx},
  cy_{header.cy},
  extra_count_{0}
{}


ResourceDialogItem::ResourceDialogItem(const details::pe_dialog_item_template& header) :
  is_extended_{false},
  help_id_{0},
  ext_style_{header.ext_style},
  style_{header.style},
  id_{header.id},
  x_{header.x},
  y_{header.y},
  cx_{header.cx},
  cy_{header.cy},
  extra_count_{0}
{}


bool ResourceDialogItem::is_extended() const {
  return is_extended_;
}

uint32_t ResourceDialogItem::extended_style() const {
  return ext_style_;
}

std::set<EXTENDED_WINDOW_STYLES> ResourceDialogItem::extended_style_list() const {
  std::set<EXTENDED_WINDOW_STYLES> ext_styles;
  std::copy_if(
      std::begin(details::extended_window_styles_array),
      std::end(details::extended_window_styles_array),
      std::inserter(ext_styles, std::begin(ext_styles)),
      [this] (EXTENDED_WINDOW_STYLES f) { return has_extended_style(f); });

  return ext_styles;

}

bool ResourceDialogItem::has_extended_style(EXTENDED_WINDOW_STYLES style) const {
  return (ext_style_ & static_cast<uint32_t>(style)) != 0;
}

uint32_t ResourceDialogItem::style() const {
  return style_;
}

std::set<WINDOW_STYLES> ResourceDialogItem::style_list() const {
  std::set<WINDOW_STYLES> styles;
  std::copy_if(
      std::begin(details::window_styles_array),
      std::end(details::window_styles_array),
      std::inserter(styles, std::begin(styles)),
      [this] (WINDOW_STYLES f) { return has_style(f); });

  return styles;
}

bool ResourceDialogItem::has_style(WINDOW_STYLES style) const {
  return (style_ & static_cast<uint32_t>(style)) != 0;
}


int16_t ResourceDialogItem::x() const {
  return x_;
}

int16_t ResourceDialogItem::y() const {
  return y_;
}

int16_t ResourceDialogItem::cx() const {
  return cx_;
}

int16_t ResourceDialogItem::cy() const {
  return cy_;
}


uint32_t ResourceDialogItem::id() const {
  return id_;
}


// Extended API
// ============
uint32_t ResourceDialogItem::help_id() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.helpID does not exist");
  }
  return help_id_;
}


const std::u16string& ResourceDialogItem::title() const {
  if (!is_extended()) {
    LIEF_WARN("This dialog is not an extended one. DLGTEMPLATEEX.title does not exist");
  }

  return title_;
}


void ResourceDialogItem::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceDialogItem::operator==(const ResourceDialogItem& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDialogItem::operator!=(const ResourceDialogItem& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceDialogItem& dialog_item) {
  const std::set<WINDOW_STYLES>& styles = dialog_item.style_list();
  std::string styles_str = std::accumulate(
     std::begin(styles),
     std::end(styles), std::string{},
     [] (const std::string& a, WINDOW_STYLES b) {
         return a.empty() ? to_string(b) : a + ", " + to_string(b);
     });

  const std::set<EXTENDED_WINDOW_STYLES>& ext_styles = dialog_item.extended_style_list();
  std::string ext_styles_str = std::accumulate(
     std::begin(ext_styles),
     std::end(ext_styles), std::string{},
     [] (const std::string& a, EXTENDED_WINDOW_STYLES b) {
         return a.empty() ? to_string(b) : a + ", " + to_string(b);
     });


  if (dialog_item.is_extended()) {
    os << "\"" << u16tou8(dialog_item.title()) << "\"";
  }
  os << ", " << std::dec << dialog_item.id();

  if (!styles_str.empty()) {
    os << ", " << styles_str;
  }

  if (!ext_styles_str.empty()) {
    os << ", " << ext_styles_str;
  }

  os << ", " << std::dec << dialog_item.x()
     << ", " << dialog_item.y()
     << ", " << dialog_item.cx()
     << ", " << dialog_item.cy();

  return os;
}



}
}

