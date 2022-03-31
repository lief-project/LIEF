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
#ifndef LIEF_PE_ATTRIBUTES_PKCS9_COUNTER_SIG_H_
#define LIEF_PE_ATTRIBUTES_PKCS9_COUNTER_SIG_H_

#include "LIEF/visibility.h"
#include "LIEF/errors.hpp"
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/SignerInfo.hpp"
#include "LIEF/PE/signature/types.hpp"

namespace LIEF {
class VectorStream;
namespace PE {

class Parser;
class SignatureParser;


//! Interface over the structure described by the OID ``1.2.840.113549.1.9.6`` (PKCS #9)
//!
//! The internal structure is described in the
//! [RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0](https://tools.ietf.org/html/rfc2985)
//!
//! ```text
//! counterSignature ATTRIBUTE ::= {
//!   WITH SYNTAX SignerInfo
//!   ID pkcs-9-at-counterSignature
//! }
//! ```
class LIEF_API PKCS9CounterSignature : public Attribute {

  friend class Parser;
  friend class SignatureParser;

  public:
  PKCS9CounterSignature();
  PKCS9CounterSignature(SignerInfo signer);
  PKCS9CounterSignature(const PKCS9CounterSignature&);
  PKCS9CounterSignature& operator=(const PKCS9CounterSignature&);

  std::unique_ptr<Attribute> clone() const override;

  //! SignerInfo as described in the RFC #2985
  inline const SignerInfo& signer() const {
    return this->signer_;
  }

  //! Print information about the attribute
  std::string print() const override;

  void accept(Visitor& visitor) const override;

  virtual ~PKCS9CounterSignature();

  private:
  SignerInfo signer_;
};

}
}

#endif
