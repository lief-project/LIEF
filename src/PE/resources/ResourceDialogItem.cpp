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

#include "LIEF/PE/utils.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/resources/ResourceDialogItem.hpp"

namespace LIEF {
namespace PE {

ResourceDialogItem::ResourceDialogItem(const ResourceDialogItem&) = default;
ResourceDialogItem& ResourceDialogItem::operator=(const ResourceDialogItem&) = default;
ResourceDialogItem::~ResourceDialogItem(void) = default;

ResourceDialogItem::ResourceDialogItem(void) :
  is_extended_{false},
  help_id_{0},
  ext_style_{0},
  style_{0},
  id_{0},
  x_{0},
  y_{0},
  cx_{0},
  cy_{0},
  window_class_{},
  title_{},
  extra_count_{0}
{}


ResourceDialogItem::ResourceDialogItem(const pe_dialog_item_template_ext *header) :
  is_extended_{true},
  help_id_{header->help_id},
  ext_style_{header->ext_style},
  style_{header->style},
  id_{header->id},
  x_{header->x},
  y_{header->y},
  cx_{header->cx},
  cy_{header->cy},
  window_class_{},
  title_{},
  extra_count_{0}
{}


ResourceDialogItem::ResourceDialogItem(const pe_dialog_item_template *header) :
  is_extended_{false},
  help_id_{0},
  ext_style_{header->ext_style},
  style_{header->style},
  id_{header->id},
  x_{header->x},
  y_{header->y},
  cx_{header->cx},
  cy_{header->cy},
  window_class_{},
  title_{},
  extra_count_{0}
{}


bool ResourceDialogItem::is_extended(void) const {
  return this->is_extended_;
}

uint32_t ResourceDialogItem::extended_style(void) const {
  return this->ext_style_;
}

std::set<EXTENDED_WINDOW_STYLES> ResourceDialogItem::extended_style_list(void) const {
  std::set<EXTENDED_WINDOW_STYLES> ext_styles;
  std::copy_if(
      std::begin(extended_window_styles_array),
      std::end(extended_window_styles_array),
      std::inserter(ext_styles, std::begin(ext_styles)),
      std::bind(&ResourceDialogItem::has_extended_style, this, std::placeholders::_1));

  return ext_styles;

}

bool ResourceDialogItem::has_extended_style(EXTENDED_WINDOW_STYLES style) const {
  return (this->ext_style_ & static_cast<uint32_t>(style)) != 0;
}

uint32_t ResourceDialogItem::style(void) const {
  return this->style_;
}

std::set<WINDOW_STYLES> ResourceDialogItem::style_list(void) const {
  std::set<WINDOW_STYLES> styles;
  std::copy_if(
      std::begin(window_styles_array),
      std::end(window_styles_array),
      std::inserter(styles, std::begin(styles)),
      std::bind(&ResourceDialogItem::has_style, this, std::placeholders::_1));

  return styles;
}

bool ResourceDialogItem::has_style(WINDOW_STYLES style) const {
  return (this->style_ & static_cast<uint32_t>(style)) != 0;
}


int16_t ResourceDialogItem::x(void) const {
  return this->x_;
}

int16_t ResourceDialogItem::y(void) const {
  return this->y_;
}

int16_t ResourceDialogItem::cx(void) const {
  return this->cx_;
}

int16_t ResourceDialogItem::cy(void) const {
  return this->cy_;
}


uint32_t ResourceDialogItem::id(void) const {
  return this->id_;
}


// Extended API
// ============
uint32_t ResourceDialogItem::help_id(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }
  return this->help_id_;
}


const std::u16string& ResourceDialogItem::title(void) const {
  if (not this->is_extended()) {
    throw not_found("This dialog is not an extended one");
  }

  return this->title_;
}


void ResourceDialogItem::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceDialogItem::operator==(const ResourceDialogItem& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDialogItem::operator!=(const ResourceDialogItem& rhs) const {
  return not (*this == rhs);
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

  if (not styles_str.empty()) {
    os << ", " << styles_str;
  }

  if (not ext_styles_str.empty()) {
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

