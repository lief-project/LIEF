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

#include "LIEF/utils.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/signature/AuthenticatedAttributes.hpp"

namespace LIEF {
namespace PE {

AuthenticatedAttributes::AuthenticatedAttributes(void) = default;
AuthenticatedAttributes::AuthenticatedAttributes(const AuthenticatedAttributes&) = default;
AuthenticatedAttributes& AuthenticatedAttributes::operator=(const AuthenticatedAttributes&) = default;
AuthenticatedAttributes::~AuthenticatedAttributes(void) = default;


const oid_t& AuthenticatedAttributes::content_type(void) const {
  return this->content_type_;
}

const std::vector<uint8_t>& AuthenticatedAttributes::message_digest(void) const {
  return this->message_digest_;
}

const std::u16string& AuthenticatedAttributes::program_name(void) const {
  return this->program_name_;
}

const std::string& AuthenticatedAttributes::more_info(void) const {
  return this->more_info_;
}

void AuthenticatedAttributes::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const AuthenticatedAttributes& authenticated_attributes) {
  constexpr uint8_t wsize = 30;
  os << std::hex << std::left;
  os << std::setw(wsize) << std::setfill(' ') << "Content type: " << authenticated_attributes.content_type()          << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Program name: " << u16tou8(authenticated_attributes.program_name()) << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "URL : "         << authenticated_attributes.more_info()             << std::endl;

  return os;
}

}
}
