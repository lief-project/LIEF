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
#ifndef LIEF_PE_CONTENT_INFO_H_
#define LIEF_PE_CONTENT_INFO_H_

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"
#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Parser;
class SignatureParser;

/** ContentInfo as described in the RFC2315 (https://tools.ietf.org/html/rfc2315#section-7)
 *
 * ```text
 * ContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   content     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 * ```
 *
 * In the case of PE signature, ContentType **must** be set to SPC_INDIRECT_DATA_OBJID
 * OID: ``1.3.6.1.4.1.311.2.1.4`` and content is defined by the structure: ``SpcIndirectDataContent``
 * ```text
 * SpcIndirectDataContent ::= SEQUENCE {
 *  data          SpcAttributeTypeAndOptionalValue,
 *  messageDigest DigestInfo
 * }
 *
 * SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
 *  type  ObjectID,
 *  value [0] EXPLICIT ANY OPTIONAL
 * }
 * ```
 *
 * For PE signature, ``SpcAttributeTypeAndOptionalValue.type``
 * is set to ``SPC_PE_IMAGE_DATAOBJ`` (OID: ``1.3.6.1.4.1.311.2.1.15``) and the value is defined by
 * ``SpcPeImageData``
 *
 * ```text
 * DigestInfo ::= SEQUENCE {
 *  digestAlgorithm  AlgorithmIdentifier,
 *  digest           OCTETSTRING
 * }
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *  algorithm  ObjectID,
 *  parameters [0] EXPLICIT ANY OPTIONAL
 * }
 * ```
 */
class LIEF_API ContentInfo : public Object {

  friend class Parser;
  friend class SignatureParser;

  public:
  ContentInfo();
  ContentInfo(const ContentInfo&);
  ContentInfo& operator=(const ContentInfo&);

  //! Return the OID that describes the content wrapped by this object.
  //! It should match SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)
  inline oid_t content_type() const {
    return content_type_;
  }

  //! Digest used to hash the file
  //!
  //! It should match LIEF::PE::SignerInfo::digest_algorithm
  inline ALGORITHMS digest_algorithm() const {
    return digest_algorithm_;
  }

  //! PE's authentihash
  //!
  //! @see LIEF::PE::Binary::authentihash
  inline const std::vector<uint8_t>& digest() const {
    return digest_;
  }

  inline const std::string& file() const {
    return file_;
  }

  void accept(Visitor& visitor) const override;

  virtual ~ContentInfo();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ContentInfo& content_info);

  private:
  oid_t content_type_;
  std::string file_;
  uint8_t flags_ = 0;
  ALGORITHMS digest_algorithm_ = ALGORITHMS::UNKNOWN;
  std::vector<uint8_t> digest_;

};

}
}

#endif
