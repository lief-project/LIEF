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
#ifndef LIEF_PE_ATTRIBUTES_MS_SPC_STATEMENT_TYPE_H_
#define LIEF_PE_ATTRIBUTES_MS_SPC_STATEMENT_TYPE_H_

#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/errors.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
class VectorStream;
namespace PE {

class Parser;
class SignatureParser;

//! Interface over the structure described by the OID ``1.3.6.1.4.1.311.2.1.11``
//!
//! The internal structure is described in the official document:
//! [Windows Authenticode Portable Executable Signature
//! Format](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
//!
//! ```raw
//! SpcStatementType ::= SEQUENCE of OBJECT IDENTIFIER
//! ```
class LIEF_API MsSpcStatementType : public Attribute {
  friend class Parser;
  friend class SignatureParser;

 public:
  MsSpcStatementType();
  MsSpcStatementType(oid_t oid);
  MsSpcStatementType(const MsSpcStatementType&);
  MsSpcStatementType& operator=(const MsSpcStatementType&);

  std::unique_ptr<Attribute> clone() const override;

  //! According to the documentation:
  //! > The SpcStatementType MUST contain one Object Identifier with either
  //! > the value ``1.3.6.1.4.1.311.2.1.21
  //! (SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID)`` or > ``1.3.6.1.4.1.311.2.1.22
  //! (SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID)``.
  inline const oid_t& oid() const { return oid_; }

  //! Print information about the attribute
  std::string print() const override;

  void accept(Visitor& visitor) const override;
  virtual ~MsSpcStatementType();

 private:
  oid_t oid_;
};

}  // namespace PE
}  // namespace LIEF

#endif
