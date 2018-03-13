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
#ifndef LIEF_PE_CONTENT_INFO_H_
#define LIEF_PE_CONTENT_INFO_H_

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

class LIEF_API ContentInfo : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  ContentInfo(void);
  ContentInfo(const ContentInfo&);
  ContentInfo& operator=(const ContentInfo&);

  //! @brief OID of the content type.
  //! This value should match ``SPC_INDIRECT_DATA_OBJID``
  const oid_t& content_type(void) const;

  const oid_t& type(void) const;

  //! @brief Algorithm (OID) used to hash the file.
  //! This value should match SignerInfo::digest_algorithm and Signature::digest_algorithm
  const oid_t& digest_algorithm(void) const;

  //! @brief The digest
  const std::vector<uint8_t>& digest(void) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~ContentInfo(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ContentInfo& content_info);

  private:
  oid_t content_type_; // SPC_INDIRECT_DATA_OBJID

  oid_t type_;         // SPC_PE_IMAGE_DATAOBJ
  //TODO: value

  oid_t digest_algorithm_; // algorithm used to hash the file (should match Signature::digest_algorithms_)
  std::vector<uint8_t> digest_; //hash value


};

}
}

#endif
