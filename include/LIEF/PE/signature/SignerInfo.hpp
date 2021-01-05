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
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"


#include "LIEF/PE/signature/types.hpp"
#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Attribute;
class Parser;
class SignatureParser;
class x509;

class LIEF_API SignerInfo : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  using encrypted_digest_t = std::vector<uint8_t>;
  SignerInfo(void);

  SignerInfo(const SignerInfo& signinfo);
  SignerInfo& operator=(SignerInfo signinfo);

  SignerInfo(SignerInfo&&);
  SignerInfo& operator=(SignerInfo&&);

  void swap(SignerInfo& other);

  //! Should be 1
  uint32_t version(void) const;

  //! Return the serial number associated with the x509 certificate
  //! used by this signer.
  //!
  //! @see
  //! LIEF::PE::x509::serial_number
  //! SignerInfo::issuer
  inline const std::vector<uint8_t>& serial_number() const {
    return this->serialno_;
  }

  //! Return the x509::issuer used by this signer
  inline const std::string& issuer() const {
    return this->issuer_;
  };

  //! Algorithm (OID) used to hash the file.
  //!
  //! This value should match LIEF::PE::ContentInfo::digest_algorithm and
  //! LIEF::PE::Signature::digest_algorithm
  ALGORITHMS digest_algorithm(void) const;

  //! Return the (public-key) algorithm used to encrypt
  //! the signature
  ALGORITHMS encryption_algorithm(void) const;

  //! Return the signature created by the signing
  //! certificate's private key
  const encrypted_digest_t& encrypted_digest(void) const;

  //! Iterator over LIEF::PE::Attribute for **authenticated** attributes
  it_const_attributes_t authenticated_attributes() const;

  //! Iterator over LIEF::PE::Attribute for **unauthenticated** attributes
  it_const_attributes_t unauthenticated_attributes() const;

  //! Return the authenticated or un-authenticated attribute matching the
  //! given PE::SIG_ATTRIBUTE_TYPES.
  //!
  //! It returns **the first** entry that matches the given type. If it can't be
  //! found, it returns a nullptr.
  const Attribute* get_attribute(PE::SIG_ATTRIBUTE_TYPES type) const;

  //! x509 certificate used by this signer. If it can't be found, it returns a nullptr
  inline const x509* cert() const {
    return this->cert_.get();
  }

  //! x509 certificate used by this signer. If it can't be found, it returns a nullptr
  inline x509* cert() {
    return this->cert_.get();
  }

  virtual void accept(Visitor& visitor) const override;

  virtual ~SignerInfo(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const SignerInfo& signer_info);

  private:
  uint32_t version_;
  std::string issuer_;
  std::vector<uint8_t> serialno_;

  ALGORITHMS digest_algorithm_     = ALGORITHMS::UNKNOWN;
  ALGORITHMS digest_enc_algorithm_ = ALGORITHMS::UNKNOWN;

  encrypted_digest_t encrypted_digest_;
  std::vector<std::unique_ptr<Attribute>> authenticated_attributes_;
  std::vector<std::unique_ptr<Attribute>> unauthenticated_attributes_;

  std::unique_ptr<x509> cert_;

};

}
}

#endif
