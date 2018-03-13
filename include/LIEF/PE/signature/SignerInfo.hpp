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
#ifndef LIEF_PE_SIGNER_INFO_H_
#define LIEF_PE_SIGNER_INFO_H_

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/AuthenticatedAttributes.hpp"

#include "LIEF/PE/signature/types.hpp"

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

class LIEF_API SignerInfo : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  SignerInfo(void);
  SignerInfo(const SignerInfo&);
  SignerInfo& operator=(const SignerInfo&);

  //! @brief Should be 1
  uint32_t version(void) const;

  //! @brief Issuer and serial number
  const issuer_t& issuer(void) const;

  //! @brief Algorithm (OID) used to hash the file.
  //! This value should match ContentInfo::digest_algorithm and Signature::digest_algorithm
  const oid_t& digest_algorithm(void) const;

  //! @brief Return the AuthenticatedAttributes object
  const AuthenticatedAttributes& authenticated_attributes(void) const;

  //! @brief Return the signature algorithm (OID)
  const oid_t& signature_algorithm(void) const;

  //! @brief Return the signature created by the signing
  //! certificate's private key
  const std::vector<uint8_t>& encrypted_digest(void) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~SignerInfo(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const SignerInfo& signer_info);

  private:
  uint32_t                 version_;
  issuer_t                 issuer_;
  oid_t                    digest_algorithm_;

  AuthenticatedAttributes authenticated_attributes_;
  oid_t                   signature_algorithm_;
  std::vector<uint8_t>    encrypted_digest_;

};

}
}

#endif
