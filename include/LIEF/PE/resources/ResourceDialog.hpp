
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
#ifndef LIEF_PE_RESOURCE_DIALOG_H
#define LIEF_PE_RESOURCE_DIALOG_H
#include <ostream>
#include <sstream>
#include <set>

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"
#include "LIEF/iterators.hpp"

#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/resources/ResourceDialogItem.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;
struct ResourcesParser;

namespace details {
struct pe_dialog_template_ext;
struct pe_dialog_template;
}

//! Representation of a dialog box
//!
//! Windows allows two kinds of dialog box:
//! * Simple one
//! * Extended one
//!
//! ResourceDialog::is_extended determine the type of the Dialog
class LIEF_API ResourceDialog : public Object {

  friend class ResourcesManager;
  friend struct ResourcesParser;

  public:
  using items_t        = std::vector<ResourceDialogItem>;
  using it_items       = ref_iterator<items_t&>;
  using it_const_items = const_ref_iterator<const items_t&>;

  ResourceDialog();
  ResourceDialog(const details::pe_dialog_template_ext& header);
  ResourceDialog(const details::pe_dialog_template& header);

  ResourceDialog(const ResourceDialog&);
  ResourceDialog& operator=(const ResourceDialog&);

  ~ResourceDialog() override;

  //! ``true`` if the dialog is an extended one
  bool is_extended() const;

  //! The extended windows styles
  uint32_t extended_style() const;

  //! Return list of LIEF::PE::EXTENDED_WINDOW_STYLES associated with the
  //! ResourceDialog::extended_style value
  std::set<EXTENDED_WINDOW_STYLES> extended_style_list() const;

  bool has_extended_style(EXTENDED_WINDOW_STYLES style) const;

  //! The style of the dialog box. This member can be a combination of LIEF::PE::WINDOW_STYLES values and
  //! LIEF::PE::DIALOG_BOX_STYLES values.
  uint32_t style() const;

  //! Return list of LIEF::PE::WINDOW_STYLES associated with the
  //! ResourceDialog::style value
  std::set<WINDOW_STYLES> style_list() const;
  bool has_style(WINDOW_STYLES style) const;

  //! Return list of LIEF::PE::DIALOG_BOX_STYLES associated with the
  //! ResourceDialog::style value
  std::set<DIALOG_BOX_STYLES> dialogbox_style_list() const;
  bool has_dialogbox_style(DIALOG_BOX_STYLES style) const;

  //! The x-coordinate, in dialog box units, of the upper-left corner of the dialog box.
  int16_t x() const;

  //! The y-coordinate, in dialog box units, of the upper-left corner of the dialog box.
  int16_t y() const;

  //! The width, in dialog box units, of the dialog box.
  int16_t cx() const;

  //! The height, in dialog box units, of the dialog box.
  int16_t cy() const;

  //! Iterator on the controls (ResourceDialogItem) that defines the Dialog (Button, Label...)
  it_const_items items() const;

  //! RESOURCE_LANGS associated with the Dialog
  uint32_t lang() const;

  //! RESOURCE_SUBLANGS associated with the Dialog
  uint32_t sub_lang() const;

  void lang(uint32_t lang);
  void sub_lang(uint32_t sub_lang);


  // Extended API
  // ============

  //! The version number of the extended dialog box template. This member must be set to 1.
  uint16_t version() const;

  //! Indicates whether a template is an extended dialog box template:
  //!
  //! * ``0xFFFF``: Extended dialog box template
  //! * Other value: Standard dialog box template
  //!
  //! @see ResourceDialog::is_extended
  uint16_t signature() const;

  //! The help context identifier for the dialog box window
  uint32_t help_id() const;

  //! The weight of the font
  uint16_t weight() const;

  //! The point size of the font to use for the text in the dialog box and its controls.
  uint16_t point_size() const;

  //! Indicates whether the font is italic. If this value is ``true``, the font is italic
  bool is_italic() const;

  //! The character to be used
  uint8_t charset() const;

  //! The title of the dialog box
  const std::u16string& title() const;

  //! The name of the typeface for the font
  const std::u16string& typeface() const;

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceDialog& dialog);

  private:
  uint16_t version_;
  uint16_t signature_;
  uint32_t help_id_;
  uint32_t ext_style_;
  uint32_t style_;

  int16_t x_;
  int16_t y_;
  int16_t cx_;
  int16_t cy_;

  std::u16string menu_;
  std::u16string window_class_;
  std::u16string title_;

  uint16_t       point_size_;
  uint16_t       weight_;
  bool           italic_;
  uint8_t        charset_;
  std::u16string typeface_;

  items_t items_;

  uint32_t lang_;
  uint32_t sublang_;
};


}
}


#endif
