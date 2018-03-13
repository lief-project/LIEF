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
#include <tuple>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"

struct mbedtls_x509_crt;

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

class LIEF_API x509 : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  //! @brief Tuple (Year, Month, Day, Hour, Minute, Second)
  using date_t = std::array<int32_t, 6>;

  x509(mbedtls_x509_crt* ca);
  x509(const x509& other);
  x509& operator=(x509 other);
  void swap(x509& other);

  //! @brief X.509 version. (1=v1, 2=v2, 3=v3)
  uint32_t version(void) const;

  //! @brief Unique id for certificate issued by a specific CA.
  std::vector<uint8_t> serial_number(void) const;

  //! @brief Signature algorithm (OID)
  oid_t signature_algorithm(void) const;

  //! @brief Start time of certificate validity
  x509::date_t valid_from(void) const;

  //! @brief End time of certificate validity
  x509::date_t valid_to(void) const;

  //! @brief Issuer informations
  std::string issuer(void) const;

  //! @brief Subject informations
  std::string subject(void) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~x509(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const x509& x509_cert);

  private:
  x509(void);
  mbedtls_x509_crt *x509_cert_;

};

}
}

#endif
