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
#ifndef LIEF_PE_SIGNATURE_PARSER_H_
#define LIEF_PE_SIGNATURE_PARSER_H_
#include <memory>
#include <string>

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"


namespace LIEF {
namespace PE {

class Parser;

class LIEF_API SignatureParser {

  friend class Parser;

  public:
  static Signature parse(const std::vector<uint8_t>& data);

  private:
  SignatureParser(const std::vector<uint8_t>& data);
  ~SignatureParser(void);
  SignatureParser(void);

  void parse_signature(void);

  void parse_header(void);
  int32_t get_signed_data_version(void);
  std::string get_signed_data_digest_algorithms(void);

  ContentInfo parse_content_info(void);
  std::string get_content_info_type(void);

  void parse_certificates(void);

  SignerInfo get_signer_info(void);
  AuthenticatedAttributes get_authenticated_attributes(void);


  size_t current_offset(void) const;
  Signature signature_;
  uint8_t* p_;
  const uint8_t* end_;
  const uint8_t* signature_ptr_;
  std::unique_ptr<VectorStream> stream_;

};

}
}

#endif
