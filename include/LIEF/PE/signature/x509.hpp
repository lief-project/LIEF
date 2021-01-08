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
#ifndef LIEF_PE_X509_H_
#define LIEF_PE_X509_H_
#include <array>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

#include "LIEF/PE/signature/types.hpp"

#include "LIEF/enums.hpp"

struct mbedtls_x509_crt;

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

class RsaInfo;

//! Interface over a x509 certificate
class LIEF_API x509 : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  //! Tuple (Year, Month, Day, Hour, Minute, Second)
  using date_t = std::array<int32_t, 6>;

  using certificates_t = std::vector<x509>;

  //! Parse x509 certificate(s) from file path
  static certificates_t parse(const std::string& path);

  //! Parse x500 certificate(s) from raw blob
  static certificates_t parse(const std::vector<uint8_t>& content);

  //! Public key scheme
  enum class KEY_TYPES  {
    NONE = 0,    ///< Unknown scheme
    RSA,         ///< RSA Scheme
    ECKEY,       ///< Elliptic-curve scheme
    ECKEY_DH,    ///< Elliptic-curve Diffie-Hellman
    ECDSA,       ///< Elliptic-curve Digital Signature Algorithm
    RSA_ALT,     ///< RSA scheme with an alternative implementation for signing and decrypting
    RSASSA_PSS,  ///< RSA Probabilistic signature scheme
  };

  //! Mirror of mbedtls's X509 Verify codes: MBEDTLS_X509_XX
  //!
  //! It must be sync with include/mbedtls/x509.h
  enum class VERIFICATION_FLAGS {
    OK                     = 0,       /**< The verification succeed  */
    BADCERT_EXPIRED        = 1 << 0,  /**< The certificate validity has expired. */
    BADCERT_REVOKED        = 1 << 1,  /**< The certificate has been revoked (is on a CRL). */
    BADCERT_CN_MISMATCH    = 1 << 2,  /**< The certificate Common Name (CN) does not match with the expected CN. */
    BADCERT_NOT_TRUSTED    = 1 << 3,  /**< The certificate is not correctly signed by the trusted CA. */
    BADCRL_NOT_TRUSTED     = 1 << 4,  /**< The CRL is not correctly signed by the trusted CA. */
    BADCRL_EXPIRED         = 1 << 5,  /**< The CRL is expired. */
    BADCERT_MISSING        = 1 << 6,  /**< Certificate was missing. */
    BADCERT_SKIP_VERIFY    = 1 << 7,  /**< Certificate verification was skipped. */
    BADCERT_OTHER          = 1 << 8,  /**< Other reason (can be used by verify callback) */
    BADCERT_FUTURE         = 1 << 9,  /**< The certificate validity starts in the future. */
    BADCRL_FUTURE          = 1 << 10, /**< The CRL is from the future */
    BADCERT_KEY_USAGE      = 1 << 11, /**< Usage does not match the keyUsage extension. */
    BADCERT_EXT_KEY_USAGE  = 1 << 12, /**< Usage does not match the extendedKeyUsage extension. */
    BADCERT_NS_CERT_TYPE   = 1 << 13, /**< Usage does not match the nsCertType extension. */
    BADCERT_BAD_MD         = 1 << 14, /**< The certificate is signed with an unacceptable hash. */
    BADCERT_BAD_PK         = 1 << 15, /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
    BADCERT_BAD_KEY        = 1 << 16, /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
    BADCRL_BAD_MD          = 1 << 17, /**< The CRL is signed with an unacceptable hash. */
    BADCRL_BAD_PK          = 1 << 18, /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
    BADCRL_BAD_KEY         = 1 << 19, /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */
  };

  x509(mbedtls_x509_crt* ca);
  x509(const x509& other);
  x509& operator=(x509 other);
  void swap(x509& other);

  //! X.509 version. (1=v1, 2=v2, 3=v3)
  uint32_t version(void) const;

  //! Unique id for certificate issued by a specific CA.
  std::vector<uint8_t> serial_number(void) const;

  //! Signature algorithm (OID)
  oid_t signature_algorithm(void) const;

  //! Start time of certificate validity
  x509::date_t valid_from(void) const;

  //! End time of certificate validity
  x509::date_t valid_to(void) const;

  //! Issuer informations
  std::string issuer(void) const;

  //! Subject informations
  std::string subject(void) const;

  //! Try to decrypt the given signature and check if it matches the given hash according to
  //! the hash algorithm provided
  bool check_signature(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature, ALGORITHMS digest) const;

  //! The raw x509 bytes (DER encoded)
  std::vector<uint8_t> raw(void) const;

  //! Return the underlying public-key scheme
  KEY_TYPES key_type() const;

  //! **If** the underlying public-key scheme is RSA, return the RSA information.
  //! Otherwise, return a nullptr
  std::unique_ptr<RsaInfo> rsa_info() const;

  //! Verify that this certificate has been used **to trust** the given certificate
  VERIFICATION_FLAGS verify(const x509& child) const;

  //! Verify that this certificate **is trusted** by the given CA list
  VERIFICATION_FLAGS is_trusted_by(const std::vector<x509>& ca) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~x509(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const x509& x509_cert);

  private:
  x509(void);
  mbedtls_x509_crt* x509_cert_ = nullptr;

};

}
}

ENABLE_BITMASK_OPERATORS(LIEF::PE::x509::VERIFICATION_FLAGS);

#endif
