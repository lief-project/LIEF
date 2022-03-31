
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
#ifndef LIEF_PE_ATTRIBUTES_SPC_SP_OPUS_INFO_H_
#define LIEF_PE_ATTRIBUTES_SPC_SP_OPUS_INFO_H_
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/errors.hpp"
#include "LIEF/PE/signature/Attribute.hpp"


namespace LIEF {
class VectorStream;
namespace PE {

class Parser;
class SignatureParser;

//! Interface over the structure described by the OID ``1.3.6.1.4.1.311.2.1.12``
//!
//! The internal structure is described in the official document:
//! [Windows Authenticode Portable Executable Signature Format](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
//!
//! ```text
//! SpcSpOpusInfo ::= SEQUENCE {
//!     programName  [0] EXPLICIT SpcString OPTIONAL,
//!     moreInfo     [1] EXPLICIT SpcLink OPTIONAL
//! }
//! ```
class LIEF_API SpcSpOpusInfo : public Attribute {

  friend class Parser;
  friend class SignatureParser;

  public:
  SpcSpOpusInfo();
  SpcSpOpusInfo(std::string program_name, std::string more_info);
  SpcSpOpusInfo(const SpcSpOpusInfo&);
  SpcSpOpusInfo& operator=(const SpcSpOpusInfo&);

  std::unique_ptr<Attribute> clone() const override;

  //! Program description provided by the publisher
  inline const std::string& program_name() const {
    return program_name_;
  }

  //! Other information such as an url
  inline const std::string& more_info() const {
    return more_info_;
  }

  //! Print information about the attribute
  std::string print() const override;

  void accept(Visitor& visitor) const override;

  virtual ~SpcSpOpusInfo();

  private:
  std::string program_name_;
  std::string more_info_;
};

}
}

#endif
