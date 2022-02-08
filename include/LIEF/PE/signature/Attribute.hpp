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
#ifndef LIEF_PE_ATTRIBUTES_H_
#define LIEF_PE_ATTRIBUTES_H_
#include <memory>
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

//! Interface over PKCS #7 attribute
class LIEF_API Attribute : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  Attribute();
  Attribute(const Attribute&);
  Attribute& operator=(const Attribute&);

  virtual std::unique_ptr<Attribute> clone() const = 0;

  //! Concrete type of the attribute
  inline virtual SIG_ATTRIBUTE_TYPES type() const {
    return type_;
  }

  //! Print information about the underlying attribute
  virtual std::string print() const = 0;

  void accept(Visitor& visitor) const override;

  virtual ~Attribute();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Attribute& Attribute);

  protected:
  Attribute(SIG_ATTRIBUTE_TYPES type);
  SIG_ATTRIBUTE_TYPES type_ = SIG_ATTRIBUTE_TYPES::UNKNOWN;
};

}
}

#endif
