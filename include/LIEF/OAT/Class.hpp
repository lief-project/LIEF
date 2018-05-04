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
#ifndef LIEF_OAT_CLASS_H_
#define LIEF_OAT_CLASS_H_

#include "LIEF/OAT/type_traits.hpp"
#include "LIEF/OAT/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/DEX.hpp"

namespace LIEF {
namespace OAT {
class Parser;

class LIEF_API Class : public Object {
  friend class Parser;

  public:
  Class(void);

  Class(OAT_CLASS_STATUS status,
      OAT_CLASS_TYPES type,
      DEX::Class* dex_class, const std::vector<uint32_t>& bitmap = {});

  Class(const Class&);
  Class& operator=(const Class&);

  bool has_dex_class(void) const;
  const DEX::Class& dex_class(void) const;
  DEX::Class& dex_class(void);

  OAT_CLASS_STATUS status(void) const;
  OAT_CLASS_TYPES type(void) const;

  const std::string& fullname(void) const;
  size_t index(void) const;

  it_methods methods(void);
  it_const_methods methods(void) const;

  const std::vector<uint32_t>& bitmap(void) const;

  bool is_quickened(const DEX::Method& m) const;
  bool is_quickened(uint32_t relative_index) const;

  uint32_t method_offsets_index(const DEX::Method& m) const;
  uint32_t method_offsets_index(uint32_t relative_index) const;

  uint32_t relative_index(const DEX::Method& m) const;
  uint32_t relative_index(uint32_t method_absolute_index) const;

  DEX::dex2dex_class_info_t dex2dex_info(void) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Class& rhs) const;
  bool operator!=(const Class& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Class& cls);

  virtual ~Class(void);

  private:
  DEX::Class* dex_class_{nullptr};

  OAT_CLASS_STATUS status_;
  OAT_CLASS_TYPES  type_;

  std::vector<uint32_t> method_bitmap_;
  methods_t methods_;

};

} // Namespace OAT
} // Namespace LIEF
#endif
