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
#ifndef LIEF_PE_AUTHENTICATED_ATTRIBUTES_H_
#define LIEF_PE_AUTHENTICATED_ATTRIBUTES_H_

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

class LIEF_API AuthenticatedAttributes : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  AuthenticatedAttributes(void);
  AuthenticatedAttributes(const AuthenticatedAttributes&);
  AuthenticatedAttributes& operator=(const AuthenticatedAttributes&);

  //! @brief Should return the ``messageDigest`` OID
  const oid_t& content_type(void) const;

  //! @brief Return an hash of the signed attributes
  const std::vector<uint8_t>& message_digest(void) const;

  //! @brief Return the program description (if any)
  const std::u16string& program_name(void) const;

  //! @brief Return an URL to website with more information about the signer
  const std::string& more_info(void) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~AuthenticatedAttributes(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const AuthenticatedAttributes& authenticated_attributes);

  private:
  oid_t content_type_; // should holds 1.2.840.113549.1.9.4

  std::vector<uint8_t> message_digest_;

  std::u16string program_name_;
  std::string    more_info_;

};

}
}

#endif
