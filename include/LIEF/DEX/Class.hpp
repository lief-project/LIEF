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
#ifndef LIEF_DEX_CLASS_H_
#define LIEF_DEX_CLASS_H_

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/DEX/type_traits.hpp"
#include "LIEF/DEX/Structures.hpp"
#include "LIEF/DEX/Method.hpp"

namespace LIEF {
namespace DEX {
class Parser;

class LIEF_API Class : public Object {
  friend class Parser;

  public:
  using access_flags_list_t = std::vector<ACCESS_FLAGS>;

  public:
  static std::string package_normalized(const std::string& pkg_name);
  static std::string fullname_normalized(const std::string& pkg_cls);
  static std::string fullname_normalized(const std::string& pkg, const std::string& cls_name);


  Class(void);
  Class(const Class&);
  Class& operator=(const Class&);

  Class(const std::string& fullname,
      uint32_t access_flags = ACCESS_FLAGS::ACC_UNKNOWN,
      Class* parent = nullptr,
      const std::string& source_filename = "");

  //! Mangled class name (e.g. ``Lcom/example/android/MyActivity;``)
  const std::string& fullname(void) const;

  //! Package Name
  std::string package_name(void) const;

  //! Class name
  std::string name(void) const;

  //! Demangled class name
  std::string pretty_name(void) const;

  //! Check if the class has the given access flag
  bool has(ACCESS_FLAGS f) const;

  //! Access flags used by this class
  access_flags_list_t access_flags(void) const;

  //! Filename associated with this class (if any)
  const std::string& source_filename(void) const;

  //! True if the current class extends another one
  bool has_parent(void) const;

  //! Parent class
  const Class& parent(void) const;
  Class& parent(void);

  //! Methods implemented in this class
  it_const_methods methods(void) const;
  it_methods methods(void);

  //! Return Methods having the given name
  it_methods methods(const std::string& name);
  it_const_methods methods(const std::string& name) const;

  //! De-optimize information
  dex2dex_class_info_t dex2dex_info(void) const;

  //! Original index in the DEX class pool
  size_t index(void) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Class& rhs) const;
  bool operator!=(const Class& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Class& cls);

  virtual ~Class(void);

  private:
  methods_t method_from_name(const std::string& name) const;

  std::string fullname_;
  uint32_t    access_flags_;
  Class*      parent_{nullptr};
  methods_t   methods_;
  std::string source_filename_;

  uint32_t original_index_;



};

} // Namespace DEX
} // Namespace LIEF
#endif
