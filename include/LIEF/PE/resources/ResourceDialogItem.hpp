
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
#ifndef LIEF_PE_RESOURCE_DIALOG_ITEM_H_
#define LIEF_PE_RESOURCE_DIALOG_ITEM_H_
#include <iostream>
#include <sstream>
#include <set>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;
struct ResourcesParser;

namespace details {
struct pe_dialog_item_template_ext;
struct pe_dialog_item_template;
}

//! This class represents an item in the ResourceDialog
class LIEF_API ResourceDialogItem : public Object {

  friend class ResourcesManager;
  friend struct ResourcesParser;

  public:
  ResourceDialogItem();
  ResourceDialogItem(const details::pe_dialog_item_template_ext& header);
  ResourceDialogItem(const details::pe_dialog_item_template& header);

  ResourceDialogItem(const ResourceDialogItem&);
  ResourceDialogItem& operator=(const ResourceDialogItem&);

  virtual ~ResourceDialogItem();

  //! ``True`` if the control is an extended one
  bool is_extended() const;

  //! The extended styles for a window
  uint32_t extended_style() const;

  //! List of PE::EXTENDED_WINDOW_STYLES associated with
  //! the ResourceDialogItem::extended_style value
  std::set<EXTENDED_WINDOW_STYLES> extended_style_list() const;

  //! Check if the DialogItem has the given PE::EXTENDED_WINDOW_STYLES
  bool has_extended_style(EXTENDED_WINDOW_STYLES style) const;

  //! The style of the control
  uint32_t style() const;

  std::set<WINDOW_STYLES> style_list() const;
  bool has_style(WINDOW_STYLES style) const;

  //! The x-coordinate, in dialog box units, of the upper-left corner of the control.
  //! This coordinate is always relative to the upper-left corner of the dialog box's client area.
  int16_t x() const;

  //! The y-coordinate, in dialog box units, of the upper-left corner of the control.
  //! This coordinate is always relative to the upper-left corner of the dialog box's client area.
  int16_t y() const;

  //! The width, in dialog box units, of the control.
  int16_t cx() const;

  //! The height, in dialog box units, of the control.
  int16_t cy() const;

  //! The control identifier.
  uint32_t id() const;


  // Extended API
  // ============

  //! The help context identifier for the control
  uint32_t help_id() const;

  //! Initial text of the control
  const std::u16string& title() const;

  void accept(Visitor& visitor) const override;

  bool operator==(const ResourceDialogItem& rhs) const;
  bool operator!=(const ResourceDialogItem& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceDialogItem& dialog_item);

  private:
  bool     is_extended_ = true;
  uint32_t help_id_ = 0;
  uint32_t ext_style_ = 0;
  uint32_t style_ = 0;
  uint32_t id_ = 0;

  int16_t x_ = 0;
  int16_t y_ = 0;
  int16_t cx_ = 0;
  int16_t cy_ = 0;

  std::u16string window_class_;
  std::u16string title_;

  uint16_t extra_count_ = 0;
};


}
}


#endif
