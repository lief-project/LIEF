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
#include "LIEF/VDEX/Header.hpp"
#include "LIEF/VDEX/hash.hpp"

#include <numeric>
#include <sstream>
#include <iomanip>

#define PRINT_FIELD_X(name,attr) \
  os << std::setw(WIDTH) << std::setfill(' ') << name << std::hex << attr << std::endl

#define PRINT_FIELD_D(name,attr) \
  os << std::setw(WIDTH) << std::setfill(' ') << name << std::dec << attr << std::endl

namespace LIEF {
namespace VDEX {

Header::Header(const Header&) = default;
Header& Header::operator=(const Header&) = default;

Header::Header(void) :
  magic_{},
  version_{0},
  nb_dex_files_{0},
  dex_size_{0},
  verifier_deps_size_{0},
  quickening_info_size_{0}
{
  std::copy(
      std::begin(VDEX::magic),
      std::end(VDEX::magic),
      std::begin(this->magic_)
  );
}

Header::magic_t Header::magic(void) const {
  return this->magic_;
}

vdex_version_t Header::version(void) const {
  return this->version_;
}

uint32_t Header::nb_dex_files(void) const {
  return this->nb_dex_files_;
}

uint32_t Header::dex_size(void) const {
  return this->dex_size_;
}

uint32_t Header::verifier_deps_size(void) const {
  return this->verifier_deps_size_;
}

uint32_t Header::quickening_info_size(void) const {
  return this->quickening_info_size_;
}

void Header::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Header::operator==(const Header& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Header& header) {
  static constexpr size_t WIDTH = 24;

  std::string magic_str;
  for (uint8_t c : header.magic()) {
    if (::isprint(c)) {
      magic_str.push_back(static_cast<char>(c));
    } else {
      std::stringstream ss;
      ss << std::dec << "'\\" << static_cast<uint32_t>(c) << "'";
      magic_str += ss.str();
    }
  }

  os << std::hex << std::left << std::showbase;

  PRINT_FIELD_X("Magic:",                magic_str);
  PRINT_FIELD_D("Version:",              header.version());
  PRINT_FIELD_D("Number of dex files:",  header.nb_dex_files());
  PRINT_FIELD_X("Dex Size:",             header.dex_size());
  PRINT_FIELD_X("Verifier Deps Size:",   header.verifier_deps_size());
  PRINT_FIELD_X("Quickening Info Size:", header.quickening_info_size());

  return os;
}

Header::~Header(void) = default;

} // Namespace VDEX
} // Namespace LIEF

