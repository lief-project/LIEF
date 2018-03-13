
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
#ifndef LIEF_PE_RESOURCE_DIALOG_ITEM_H_
#define LIEF_PE_RESOURCE_DIALOG_ITEM_H_
#include <iostream>
#include <sstream>
#include <set>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;

class LIEF_API ResourceDialogItem : public Object {

  friend class ResourcesManager;

  public:
  ResourceDialogItem(void);
  ResourceDialogItem(const pe_dialog_item_template_ext *header);
  ResourceDialogItem(const pe_dialog_item_template *header);

  ResourceDialogItem(const ResourceDialogItem&);
  ResourceDialogItem& operator=(const ResourceDialogItem&);

  virtual ~ResourceDialogItem(void);

  //! @brief ``True`` if the control is an extended one
  bool is_extended(void) const;

  //! @brief The extended styles for a window
  uint32_t extended_style(void) const;

  //! @brief List of PE::EXTENDED_WINDOW_STYLES associated with
  //! the ResourceDialogItem::extended_style value
  std::set<EXTENDED_WINDOW_STYLES> extended_style_list(void) const;

  //! @brief Check if the DialogItem has the given PE::EXTENDED_WINDOW_STYLES
  bool has_extended_style(EXTENDED_WINDOW_STYLES style) const;

  //! @brief The style of the control
  uint32_t style(void) const;

  std::set<WINDOW_STYLES> style_list(void) const;
  bool has_style(WINDOW_STYLES style) const;

  //! @brief The x-coordinate, in dialog box units, of the upper-left corner of the control.
  //! This coordinate is always relative to the upper-left corner of the dialog box's client area.
  int16_t x(void) const;

  //! @brief The y-coordinate, in dialog box units, of the upper-left corner of the control.
  //! This coordinate is always relative to the upper-left corner of the dialog box's client area.
  int16_t y(void) const;

  //! @brief The width, in dialog box units, of the control.
  int16_t cx(void) const;

  //! @brief The height, in dialog box units, of the control.
  int16_t cy(void) const;

  //! @brief The control identifier.
  uint32_t id(void) const;


  // Extended API
  // ============

  //! @brief The help context identifier for the control
  uint32_t help_id(void) const;

  //! @brief Initial text of the control
  const std::u16string& title(void) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceDialogItem& rhs) const;
  bool operator!=(const ResourceDialogItem& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceDialogItem& dialog_item);

  private:
  bool     is_extended_;
  uint32_t help_id_;
  uint32_t ext_style_;
  uint32_t style_;
  uint32_t id_;

  int16_t x_;
  int16_t y_;
  int16_t cx_;
  int16_t cy_;

  std::u16string window_class_;
  std::u16string title_;

  uint16_t extra_count_;
};


}
}


#endif
