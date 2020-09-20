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

#include <iomanip>

#include "LIEF/utils.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/signature/SpcIndirectDataContent.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/SignatureUtils.hpp"

namespace LIEF {
namespace PE {

SpcIndirectDataContent::SpcIndirectDataContent(void) = default;
SpcIndirectDataContent::SpcIndirectDataContent(const SpcIndirectDataContent&) = default;
SpcIndirectDataContent& SpcIndirectDataContent::operator=(const SpcIndirectDataContent&) = default;
SpcIndirectDataContent::~SpcIndirectDataContent(void) = default;

void SpcIndirectDataContent::accept(Visitor &visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const SpcIndirectDataContent& spc_indirect_data_content) {
  constexpr uint8_t wsize = 30;

  os << std::hex << std::left;
  os << std::setw(wsize) << std::setfill(' ')
     << "Type: "             << oid_to_string(spc_indirect_data_content.type())         << std::endl;
  os << std::setw(wsize) << std::setfill(' ')
     << "Digest Algorithm: " << oid_to_string(spc_indirect_data_content.digest_algorithm()) << std::endl;
  os << std::setw(wsize) << std::setfill(' ')
     << "SpcPeImageFlags: " << to_string(spc_indirect_data_content.flags()) << std::endl;

  const auto& spc_link = spc_indirect_data_content.file();
  os << std::setw(wsize) << std::setfill(' ')
     << "SpcLink: " << (!spc_link.empty() ? spc_link : "N/A") << std::endl;
  return os;
}

const oid_t& SpcIndirectDataContent::type(void) const {
  return this->type_;
}

const oid_t& SpcIndirectDataContent::digest_algorithm(void) const {
  return this->digest_algorithm_;
}

const std::vector<uint8_t>& SpcIndirectDataContent::digest(void) const {
  return this->digest_;
}

const std::string& SpcIndirectDataContent::file() const {
  return this->file_;
}

SPC_PE_IMAGE_FLAGS SpcIndirectDataContent::flags(void) const {
  return this->flags_;
}

}
}

