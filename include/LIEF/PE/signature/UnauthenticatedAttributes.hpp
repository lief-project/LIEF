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

  size_t number_of_nested_signatures(void) const;
  size_t number_of_counter_signatures(void) const;
  size_t number_of_timestamping_signatures(void) const;

  const Signature& nested_signature(const size_t i) const;
  const SignerInfo& counter_signature(const size_t i) const;
  const SignerInfo& timestamping_signature(const size_t i) const;

  const std::vector<std::unique_ptr<Signature>>& nested_signatures(void) const;
  const std::vector<std::unique_ptr<SignerInfo>>& counter_signatures(void) const;
  const std::vector<std::unique_ptr<SignerInfo>>& timestamping_signatures(void) const;

  bool has_nested_signatures() const;
  bool has_counter_signatures() const;
  bool has_timestamping_signatures() const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~UnauthenticatedAttributes(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const UnauthenticatedAttributes& authenticated_attributes);

  private:

  std::vector<std::unique_ptr<Signature>> nested_signatures_;
  std::vector<std::unique_ptr<SignerInfo>> counter_signatures_;
  std::vector<std::unique_ptr<SignerInfo>> timestamping_signatures_;

};

}
}

#endif
