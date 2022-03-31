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
#ifndef LIEF_PE_ATTRIBUTES_CONTENT_TYPE_H_
#define LIEF_PE_ATTRIBUTES_CONTENT_TYPE_H_
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/errors.hpp"
#include "LIEF/PE/signature/Attribute.hpp"


namespace LIEF {
class VectorStream;
namespace PE {

class Parser;
class SignatureParser;

//! Interface over the structure described by the OID ``1.2.840.113549.1.9.3`` (PKCS #9)
//!
//! The internal structure is described in the
//! [RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0](https://tools.ietf.org/html/rfc2985)
//!
//! ```text
//! ContentType ::= OBJECT IDENTIFIER
//! ```
class LIEF_API ContentType : public Attribute {

  friend class Parser;
  friend class SignatureParser;

  public:
  ContentType();
  ContentType(oid_t oid);
  ContentType(const ContentType&);
  ContentType& operator=(const ContentType&);

  //! OID as described in RFC #2985
  inline const oid_t& oid() const {
    return oid_;
  }

  //! Print information about the attribute
  std::string print() const override;

  std::unique_ptr<Attribute> clone() const override;

  void accept(Visitor& visitor) const override;
  virtual ~ContentType();

  private:
  oid_t oid_;
};

}
}

#endif
