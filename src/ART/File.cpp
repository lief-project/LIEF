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


#include "LIEF/ART/File.hpp"
#include "LIEF/ART/hash.hpp"

namespace LIEF {
namespace ART {

File::File(void) :
  header_{}
{}


const Header& File::header(void) const {
  return this->header_;
}

Header& File::header(void) {
  return const_cast<Header&>(static_cast<const File*>(this)->header());
}

void File::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool File::operator==(const File& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool File::operator!=(const File& rhs) const {
  return not (*this == rhs);
}


File::~File(void) = default;

std::ostream& operator<<(std::ostream& os, const File& art_file) {
  os << art_file.header();
  return os;
}

} // Namespace ART
} // Namespace LIEF
