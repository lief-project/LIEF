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
#include "LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"

#include <spdlog/fmt/fmt.h>
namespace LIEF {
namespace PE {

PKCS9SigningTime::PKCS9SigningTime()
    : Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_SIGNING_TIME) {}

PKCS9SigningTime::PKCS9SigningTime(const PKCS9SigningTime&) = default;
PKCS9SigningTime& PKCS9SigningTime::operator=(const PKCS9SigningTime&) =
    default;

std::unique_ptr<Attribute> PKCS9SigningTime::clone() const {
  return std::unique_ptr<Attribute>(new PKCS9SigningTime{*this});
}

PKCS9SigningTime::PKCS9SigningTime(time_t time)
    : Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_SIGNING_TIME), time_{time} {}

void PKCS9SigningTime::accept(Visitor& visitor) const { visitor.visit(*this); }

std::string PKCS9SigningTime::print() const {
  const time_t& time = this->time();
  return fmt::format("{}/{}/{} - {}:{}:{}", time[0], time[1], time[2], time[3],
                     time[4], time[5]);
}

PKCS9SigningTime::~PKCS9SigningTime() = default;

}  // namespace PE
}  // namespace LIEF
