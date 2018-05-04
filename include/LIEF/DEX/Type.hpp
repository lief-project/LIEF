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
#ifndef LIEF_DEX_TYPE_H_
#define LIEF_DEX_TYPE_H_

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

namespace LIEF {
namespace DEX {
class Parser;

class LIEF_API Type : public Object {
  friend class Parser;

  public:
  enum class TYPES {
    UNKNOWN   = 0,
    PRIMITIVE = 1,
    CLASS     = 2,
    ARRAY     = 3,
  };

  enum class PRIMITIVES {
    VOID_T  = 0x01,
    BOOLEAN = 0x02,
    BYTE    = 0x03,
    SHORT   = 0x04,
    CHAR    = 0x05,
    INT     = 0x06,
    LONG    = 0x07,
    FLOAT   = 0x08,
    DOUBLE  = 0x09,
  };

  using array_t = std::vector<Type>;

  public:
  static std::string pretty_name(PRIMITIVES p);

  public:
  Type(void);
  Type(const std::string& mangled);
  Type(const Type& other);

  TYPES type(void) const;

  const Class& cls(void) const;
  const array_t& array(void) const;
  const PRIMITIVES& primitive(void) const;

  Class& cls(void);
  array_t& array(void);
  PRIMITIVES& primitive(void);

  //! Return the array dimension if the current is
  //! an array. Otherwise it returns 0
  size_t dim(void) const;

  const Type& underlying_array_type(void) const;
  Type& underlying_array_type(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Type& rhs) const;
  bool operator!=(const Type& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Type& type);

  virtual ~Type(void);

  private:
  void parse(const std::string& type);

  TYPES type_{TYPES::UNKNOWN};
  union {
    Class* cls_{nullptr};
    array_t* array_;
    PRIMITIVES* basic_;
  };




};

} // Namespace DEX
} // Namespace LIEF
#endif
