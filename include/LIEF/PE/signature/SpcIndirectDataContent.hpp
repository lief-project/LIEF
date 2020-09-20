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
#ifndef LIEF_PE_SPC_INDIRECT_DATA_CONTENT_H_
#define LIEF_PE_SPC_INDIRECT_DATA_CONTENT_H_

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"
#include "LIEF/PE/signature/ContentInfo.hpp"

namespace LIEF {
namespace PE {

// https://docs.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-spc_indirect_data_content
class LIEF_API SpcIndirectDataContent : public ContentInfo {

  friend class Parser;
  friend class SignatureParser;

  public:

  SpcIndirectDataContent(void);
  SpcIndirectDataContent(const SpcIndirectDataContent&);
  SpcIndirectDataContent& operator=(const SpcIndirectDataContent&);

  virtual void accept(Visitor& visitor) const override;

  virtual ~SpcIndirectDataContent(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const SpcIndirectDataContent& authenticated_attributes);

  //! @brief Algorithm (OID) used to hash the file.
  //! This value should match SignerInfo::digest_algorithm and Signature::digest_algorithm
  const oid_t& digest_algorithm(void) const;

  //! @brief This field specifies which portions of the Windows PE file are hashed.
  SPC_PE_IMAGE_FLAGS flags(void) const;

  //! @brief This field is always set to an SPCLink structure,
  //! even though the ASN.1 definitions designate file as optional.
  const std::string& file(void) const;

  //! @brief This field is set to SPC_PE_IMAGE_DATAOBJ OID (1.3.6.1.4.1.311.2.1.15).
  const oid_t& type(void) const;

  //! @brief The digest
  const std::vector<uint8_t>& digest(void) const;

  private:

  oid_t digest_algorithm_; // algorithm used to hash the file (should match Signature::digest_algorithms_)
  SPC_PE_IMAGE_FLAGS flags_ = static_cast<SPC_PE_IMAGE_FLAGS>(0);
  std::string file_;

  oid_t type_;         // SPC_PE_IMAGE_DATAOBJ
  std::vector<uint8_t> digest_; //hash value
};

}
}

#endif
