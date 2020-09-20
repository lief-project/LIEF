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

  //! @brief Return the raw bytes associated with the ContentInfo
  const std::vector<uint8_t>& raw(void) const;

  virtual void accept(Visitor& visitor) const override;

  virtual ~ContentInfo(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ContentInfo& content_info);

  private:
  oid_t content_type_; // e.g., SPC_INDIRECT_DATA_OBJID
  std::vector<uint8_t> raw_; // raw bytes
};

}
}

#endif
