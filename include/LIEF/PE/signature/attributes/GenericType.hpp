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
#ifndef LIEF_PE_ATTRIBUTES_GENERIC_TYPE_H_
#define LIEF_PE_ATTRIBUTES_GENERIC_TYPE_H_
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/errors.hpp"
#include "LIEF/PE/signature/Attribute.hpp"


namespace LIEF {
class VectorStream;
namespace PE {

class Parser;
class SignatureParser;

//! Interface over an attribute for which the internal structure is not supported by LIEF
class LIEF_API GenericType : public Attribute {

  friend class Parser;
  friend class SignatureParser;

  public:
  GenericType();
  GenericType(oid_t oid, std::vector<uint8_t> raw);
  GenericType(const GenericType&);
  GenericType& operator=(const GenericType&);

  std::unique_ptr<Attribute> clone() const override;

  //! OID of the original attribute
  inline const oid_t& oid() const {
    return oid_;
  }

  //! Original DER blob of the attribute
  inline const std::vector<uint8_t>& raw_content() const {
    return raw_;
  }

  //! Print information about the attribute
  std::string print() const override;

  void accept(Visitor& visitor) const override;

  virtual ~GenericType();

  private:
  oid_t oid_;
  std::vector<uint8_t> raw_;
};

}
}

#endif
