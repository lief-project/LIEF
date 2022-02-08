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
#include <sstream>
#include <numeric>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/CodeView.hpp"

namespace LIEF {
namespace PE {

CodeView::CodeView(const CodeView&) = default;
CodeView& CodeView::operator=(const CodeView&) = default;
CodeView::~CodeView() = default;

CodeView::CodeView() :
  cv_signature_{CODE_VIEW_SIGNATURES::CVS_UNKNOWN}
{}


CodeView::CodeView(CODE_VIEW_SIGNATURES cv_signature) :
  cv_signature_{cv_signature}
{}



CODE_VIEW_SIGNATURES CodeView::cv_signature() const {
  return cv_signature_;
}


void CodeView::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool CodeView::operator==(const CodeView& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CodeView::operator!=(const CodeView& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const CodeView& entry) {
  static constexpr size_t WIDTH = 22;

  os << std::hex;
  os << std::left;
  os << std::setfill(' ');

  os << std::setw(WIDTH) << "Code View Signature:" << to_string(entry.cv_signature())  << std::endl;
  return os;
}

} // namespace PE
} // namespace LIEF
