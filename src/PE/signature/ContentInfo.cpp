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
#include <iomanip>

#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/ContentInfo.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/utils.hpp"

namespace LIEF {
namespace PE {

ContentInfo::ContentInfo() = default;
ContentInfo::ContentInfo(const ContentInfo&) = default;
ContentInfo& ContentInfo::operator=(const ContentInfo&) = default;
ContentInfo::~ContentInfo() = default;


void ContentInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& operator<<(std::ostream& os, const ContentInfo& content_info) {
  os << "Authentihash: " << hex_dump(content_info.digest())
     << "(" << to_string(content_info.digest_algorithm()) << ")\n";

  return os;
}

}
}
