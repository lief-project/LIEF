/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/Visitor.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/PE/signature/SpcIndirectData.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include <spdlog/fmt/fmt.h>

namespace LIEF {
namespace PE {

static constexpr const char SPC_INDIRECT_DATA_OBJID[] = "1.3.6.1.4.1.311.2.1.4";

SpcIndirectData::SpcIndirectData() :
  ContentInfo::Content(SPC_INDIRECT_DATA_OBJID)
{}

SpcIndirectData::~SpcIndirectData() = default;

SpcIndirectData::SpcIndirectData(const SpcIndirectData&) = default;
SpcIndirectData& SpcIndirectData::operator=(const SpcIndirectData&) = default;

void SpcIndirectData::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SpcIndirectData::classof(const ContentInfo::Content* content) {
  return content->content_type() == SPC_INDIRECT_DATA_OBJID;
}

void SpcIndirectData::print(std::ostream& os) const {
  if (!file().empty()) {
    os << fmt::format("{} - {} - {}\n", to_string(digest_algorithm()),
                      file(), hex_dump(digest()));
  } else {
    os << fmt::format("{}: {}\n", to_string(digest_algorithm()), hex_dump(digest()));
  }
}

}
}
