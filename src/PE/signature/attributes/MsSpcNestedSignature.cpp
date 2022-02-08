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
#include <sstream>

#include "LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"

namespace LIEF {
namespace PE {

MsSpcNestedSignature::MsSpcNestedSignature() :
  Attribute(SIG_ATTRIBUTE_TYPES::MS_SPC_NESTED_SIGN)
{}

MsSpcNestedSignature::MsSpcNestedSignature(const MsSpcNestedSignature&) = default;
MsSpcNestedSignature& MsSpcNestedSignature::operator=(const MsSpcNestedSignature&) = default;

MsSpcNestedSignature::MsSpcNestedSignature(Signature sig) :
  Attribute(SIG_ATTRIBUTE_TYPES::MS_SPC_NESTED_SIGN),
  sig_{std::move(sig)}
{}

std::unique_ptr<Attribute> MsSpcNestedSignature::clone() const {
  return std::unique_ptr<Attribute>(new MsSpcNestedSignature{*this});
}


void MsSpcNestedSignature::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string MsSpcNestedSignature::print() const {
  std::ostringstream oss;
  oss << "Nested signature:\n";
  oss << sig();
  return oss.str();
}


MsSpcNestedSignature::~MsSpcNestedSignature() = default;

}
}
