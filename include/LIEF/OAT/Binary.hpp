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
#ifndef LIEF_OAT_BINARY_H_
#define LIEF_OAT_BINARY_H_
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/ELF/Binary.hpp"

#include "LIEF/DEX.hpp"

#include "LIEF/OAT/type_traits.hpp"
#include "LIEF/OAT/Header.hpp"
#include "LIEF/OAT/DexFile.hpp"
#include "LIEF/OAT/Class.hpp"
#include "LIEF/OAT/Method.hpp"

namespace LIEF {
namespace VDEX {
class File;
}
namespace OAT {
class Parser;

class LIEF_API Binary : public LIEF::ELF::Binary {
  friend class Parser;

  public:
  Binary& operator=(const Binary& copy) = delete;
  Binary(const Binary& copy)            = delete;

  //! OAT Header
  const Header& header(void) const;
  Header& header(void);

  //! Iterator over LIEF::DEX::File
  DEX::it_dex_files dex_files(void);
  DEX::it_const_dex_files dex_files(void) const;

  //! Iterator over LIEF::OAT::DexFile
  it_dex_files       oat_dex_files(void);
  it_const_dex_files oat_dex_files(void) const;

  //! Iterator over LIEF::OAT::Class
  it_const_classes classes(void) const;
  it_classes classes(void);

  //! Check the current OAT has the given class
  bool has_class(const std::string& class_name) const;


  //! Return the LIEF::OAT::Class with the given name
  const Class& get_class(const std::string& class_name) const;

  Class& get_class(const std::string& class_name);

  //! Return the LIEF::OAT::Class at the given index
  const Class& get_class(size_t index) const;

  Class& get_class(size_t index);

  //! Iterator over LIEF::OAT::Method
  it_const_methods methods(void) const;
  it_methods methods(void);

  dex2dex_info_t dex2dex_info(void) const;

  std::string dex2dex_json_info(void);

  bool operator==(const Binary& rhs) const;
  bool operator!=(const Binary& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~Binary(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Binary& binary);

  private:
  Binary(void);

  Header           header_;
  DEX::dex_files_t dex_files_;

  dex_files_t oat_dex_files_;
  classes_t   classes_;
  methods_t   methods_;

  // For OAT > 79
  VDEX::File* vdex_{nullptr};


};

}
}

#endif
