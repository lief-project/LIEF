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
#include <iomanip>

#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/ContentInfo.hpp"

namespace LIEF {
namespace PE {

ContentInfo::ContentInfo(void) = default;
ContentInfo::ContentInfo(const ContentInfo&) = default;
ContentInfo& ContentInfo::operator=(const ContentInfo&) = default;
ContentInfo::~ContentInfo(void) = default;

const oid_t& ContentInfo::content_type(void) const {
  return this->content_type_;
}

const oid_t& ContentInfo::type(void) const {
  return this->type_;
}


const oid_t& ContentInfo::digest_algorithm(void) const {
  return this->digest_algorithm_;
}


const std::vector<uint8_t>& ContentInfo::digest(void) const {
  return this->digest_;
}


void ContentInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& operator<<(std::ostream& os, const ContentInfo& content_info) {
  constexpr uint8_t wsize = 30;

  os << std::hex << std::left;
  os << std::setw(wsize) << std::setfill(' ') << "Content Type: "     << oid_to_string(content_info.content_type()) << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Type: "             << oid_to_string(content_info.type())         << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Digest Algorithm: " << oid_to_string(content_info.digest_algorithm()) << std::endl;

  return os;
}

}
}
