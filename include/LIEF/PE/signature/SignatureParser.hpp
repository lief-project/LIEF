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
#ifndef LIEF_PE_SIGNATURE_PARSER_H_
#define LIEF_PE_SIGNATURE_PARSER_H_
#include <memory>
#include <string>
#include <array>

#include "LIEF/errors.hpp"

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

namespace LIEF {
class VectorStream;

namespace PE {
class Parser;
class Attribute;

class LIEF_API SignatureParser {
  friend class Parser;
  struct SpcPeImageData {
    uint32_t flags;
    std::string file;
  };

  struct SpcSpOpusInfo {
    std::string program_name;
    std::string more_info;
  };
  struct range_t {
    uint64_t start = 0;
    uint64_t end = 0;
  };

  public:
  using attributes_t = std::vector<std::unique_ptr<Attribute>>;
  using signer_infos_t = std::vector<SignerInfo>;
  using x509_certificates_t = std::vector<x509>;
  using time_t = std::array<int32_t, 6>;

  //! Parse a PKCS #7 signature given a raw blob
  static result<Signature> parse(std::vector<uint8_t> data, bool skip_header = false);

  //! Parse a PKCS #7 signature from a file path
  static result<Signature> parse(const std::string& path);
  SignatureParser(const SignatureParser&) = delete;
  SignatureParser& operator=(const SignatureParser&) = delete;
  private:
  SignatureParser(std::vector<uint8_t> data);
  ~SignatureParser();
  SignatureParser();

  result<Signature> parse_signature();

  static result<ContentInfo> parse_content_info(VectorStream& stream, range_t& range);
  static result<x509_certificates_t> parse_certificates(VectorStream& stream);
  result<signer_infos_t> parse_signer_infos(VectorStream& stream);
  result<attributes_t> parse_attributes(VectorStream& stream);
  static result<std::unique_ptr<Attribute>> parse_content_type(VectorStream& stream);

  result<signer_infos_t> parse_pkcs9_counter_sign(VectorStream& stream);
  static result<std::vector<uint8_t>> parse_pkcs9_message_digest(VectorStream& stream);
  static result<int32_t> parse_pkcs9_at_sequence_number(VectorStream& stream);
  static result<time_t> parse_pkcs9_signing_time(VectorStream& stream);

  static result<void> parse_ms_counter_sign(VectorStream& stream);
  static result<Signature> parse_ms_spc_nested_signature(VectorStream& stream);
  result<oid_t> parse_ms_spc_statement_type(VectorStream& stream);

  result<SpcSpOpusInfo> parse_spc_sp_opus_info(VectorStream& stream);
  static result<std::string> parse_spc_string(VectorStream& stream);
  static result<std::string> parse_spc_link(VectorStream& stream);
  static result<SpcPeImageData> parse_spc_pe_image_data(VectorStream& stream);
  size_t current_offset() const;
  std::unique_ptr<VectorStream> stream_;
};

}
}

#endif
