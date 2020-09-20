/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
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
#ifndef LIEF_PE_UNAUTHENTICATED_ATTRIBUTES_H_
#define LIEF_PE_UNAUTHENTICATED_ATTRIBUTES_H_

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"

#include <memory>

namespace LIEF {
namespace PE {

class Signature;
class SignerInfo;

class LIEF_API UnauthenticatedAttributes : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  UnauthenticatedAttributes(void);
  UnauthenticatedAttributes(UnauthenticatedAttributes&&);
  UnauthenticatedAttributes& operator=(UnauthenticatedAttributes&&);

  //! @brief Should return the ``messageDigest`` OID
  const oid_t& content_type(void) const;

  const Signature& nested_signature(void) const;
  const SignerInfo& counter_signature(void) const;
  const SignerInfo& timestamping_signature(void) const;

  bool is_nested_signature() const;
  bool is_counter_signature() const;
  bool is_timestamping_signature() const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~UnauthenticatedAttributes(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const UnauthenticatedAttributes& authenticated_attributes);

  private:
  oid_t content_type_;

  std::unique_ptr<Signature> nested_signature_;
  std::unique_ptr<SignerInfo> counter_signature_;
  std::unique_ptr<SignerInfo> timestamping_signature_;

};

}
}

#endif
