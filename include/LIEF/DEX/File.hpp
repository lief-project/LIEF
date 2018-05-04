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
#ifndef LIEF_DEX_FILE_H_
#define LIEF_DEX_FILE_H_

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/DEX/type_traits.hpp"
#include "LIEF/DEX/Header.hpp"
#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/Method.hpp"
#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/Prototype.hpp"
#include "LIEF/DEX/instructions.hpp"
#include "LIEF/DEX/MapList.hpp"

namespace LIEF {
namespace DEX {
class Parser;

class LIEF_API File : public Object {
  friend class Parser;

  public:
  File& operator=(const File& copy) = delete;
  File(const File& copy)            = delete;


  //! Version of the current DEX file
  dex_version_t version(void) const;

  //! Name of this file
  const std::string& name(void) const;

  void name(const std::string& name);

  //! Location of this file
  const std::string& location(void) const;
  void location(const std::string& location);

  //! DEX header
  const Header& header(void) const;
  Header& header(void);

  //! **All** classes used in the DEX file
  it_const_classes classes(void) const;
  it_classes classes(void);

  //! Check if the given class name exists
  bool has_class(const std::string& class_name) const;

  //! Return the DEX::Class object associated with the given name
  const Class& get_class(const std::string& class_name) const;

  Class& get_class(const std::string& class_name);

  //! Return the DEX::Class object associated with the given index
  const Class& get_class(size_t index) const;

  Class& get_class(size_t index);


  //! De-optimize information
  dex2dex_info_t dex2dex_info(void) const;

  //! De-optimize information as JSON
  std::string dex2dex_json_info(void);

  //bool has_method(const std::string& method_name) const;

  //const Method& get_method(const std::string& method_name) const;

  //Method& get_method(const std::string& method_name);

  //! **All** Methods used in this DEX
  it_const_methods methods(void) const;
  it_methods methods(void);

  //! String pool
  it_const_strings strings(void) const;
  it_strings strings(void);

  //! Type pool
  it_const_types types(void) const;
  it_types types(void);

  //! Prototype pool
  it_const_protypes prototypes(void) const;
  it_protypes prototypes(void);

  //! DEX Map
  const MapList& map(void) const;
  MapList& map(void);


  //! Extract the current dex file and deoptimize it
  std::string save(const std::string path = "", bool deoptimize = true) const;

  std::vector<uint8_t> raw(bool deoptimize = true) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const File& rhs) const;
  bool operator!=(const File& rhs) const;

  virtual ~File(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const File& file);

  private:
  File(void);

  void add_class(Class* cls);

  static void deoptimize_nop(uint8_t* inst_ptr, uint32_t value);
  static void deoptimize_return(uint8_t* inst_ptr, uint32_t value);
  static void deoptimize_invoke_virtual(uint8_t* inst_ptr, uint32_t value, OPCODES new_inst);
  static void deoptimize_instance_field_access(uint8_t* inst_ptr, uint32_t value, OPCODES new_inst);

  std::string name_;
  std::string location_;

  Header       header_;
  classes_t    classes_;
  methods_t    methods_;
  strings_t    strings_;
  types_t      types_;
  prototypes_t prototypes_;
  MapList      map_;
  std::vector<Class*> class_list_;

  std::vector<uint8_t> original_data_;
};

}
}

#endif
