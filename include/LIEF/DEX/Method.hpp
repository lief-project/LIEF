/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#ifndef LIEF_DEX_METHOD_H_
#define LIEF_DEX_METHOD_H_

#include "LIEF/DEX/type_traits.hpp"
#include "LIEF/DEX/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/DEX/CodeInfo.hpp"
#include "LIEF/DEX/Prototype.hpp"

namespace LIEF {
namespace DEX {
class Parser;
class Class;

class LIEF_API Method : public Object {
  friend class Parser;
  public:
  using access_flags_list_t = std::vector<ACCESS_FLAGS>;

  public:
  using bytecode_t = std::vector<uint8_t>;
  Method();
  Method(const std::string& name, Class* parent = nullptr);

  Method(const Method&);
  Method& operator=(const Method&);

  //! Name of the Method
  const std::string& name() const;

  //! True if a class is associated with this method
  bool has_class() const;

  //! Class associated with this Method
  const Class& cls() const;
  Class& cls();

  //! Offset to the Dalvik Bytecode
  uint64_t code_offset() const;

  //! Dalvik Bytecode
  const bytecode_t& bytecode() const;

  //! Index in the DEX Methods pool
  size_t index() const;

  //! True if this method is a virtual one.
  //! i.e. not **static**, **private**, **finale** or constructor
  bool is_virtual() const;

  //! Method's prototype
  const Prototype& prototype() const;
  Prototype& prototype();

  void insert_dex2dex_info(uint32_t pc, uint32_t index);

  virtual void accept(Visitor& visitor) const override;

  const dex2dex_method_info_t& dex2dex_info() const;

  bool has(ACCESS_FLAGS f) const;

  access_flags_list_t access_flags() const;

  //bool is_public() const;
  //bool is_private() const;
  //bool is_protected() const;
  //bool is_static() const;

  bool operator==(const Method& rhs) const;
  bool operator!=(const Method& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Method& mtd);

  virtual ~Method();

  private:
  void set_virtual(bool v);

  private:
  std::string name_;
  Class* parent_{nullptr};
  Prototype* prototype_{nullptr};
  uint32_t access_flags_;
  uint32_t original_index_;
  bool is_virtual_;

  uint64_t code_offset_;
  std::vector<uint8_t> bytecode_;

  CodeInfo code_info_;

  dex2dex_method_info_t dex2dex_info_;

};

} // Namespace DEX
} // Namespace LIEF
#endif
