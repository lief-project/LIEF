/* Copyright 2021 - 2022 R. Thomas
 * Copyright 2021 - 2022 Quarkslab
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
#include "LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"
namespace LIEF {
namespace PE {

SpcSpOpusInfo::SpcSpOpusInfo() :
  Attribute(SIG_ATTRIBUTE_TYPES::SPC_SP_OPUS_INFO)
{}

SpcSpOpusInfo::SpcSpOpusInfo(const SpcSpOpusInfo&) = default;
SpcSpOpusInfo& SpcSpOpusInfo::operator=(const SpcSpOpusInfo&) = default;

std::unique_ptr<Attribute> SpcSpOpusInfo::clone() const {
  return std::unique_ptr<Attribute>(new SpcSpOpusInfo{*this});
}

SpcSpOpusInfo::SpcSpOpusInfo(std::string program_name, std::string more_info) :
  Attribute(SIG_ATTRIBUTE_TYPES::SPC_SP_OPUS_INFO),
  program_name_{std::move(program_name)},
  more_info_{std::move(more_info)}
{}

void SpcSpOpusInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string SpcSpOpusInfo::print() const {
  std::string out;
  if (!program_name().empty()) {
    out = program_name();
  }
  if (!more_info().empty()) {
    if (!out.empty()) {
      out += " - ";
    }
    out += more_info();
  }
  return out;
}


SpcSpOpusInfo::~SpcSpOpusInfo() = default;

}
}
