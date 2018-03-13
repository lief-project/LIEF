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
#include <numeric>

#include "LIEF/Abstract/Header.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

namespace LIEF {
Header::Header(const Header&) = default;
Header& Header::operator=(const Header&) = default;
Header::~Header(void) = default;


Header::Header(void) :
  architecture_{ARCHITECTURES::ARCH_NONE},
  modes_{},
  object_type_{OBJECT_TYPES::TYPE_NONE},
  entrypoint_{0},
  endianness_{ENDIANNESS::ENDIAN_NONE}
{}


ARCHITECTURES Header::architecture(void) const {
  return this->architecture_;
}


OBJECT_TYPES Header::object_type(void) const {
  return this->object_type_;
}


const std::set<MODES>& Header::modes(void) const {
  return this->modes_;
}


bool Header::is_32(void) const {
  return this->modes().count(MODES::MODE_32) > 0;
}


bool Header::is_64(void) const {
  return this->modes().count(MODES::MODE_64) > 0;
}


uint64_t Header::entrypoint(void) const {
  return this->entrypoint_;
}


ENDIANNESS Header::endianness(void) const {
  return this->endianness_;
}


void Header::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


void Header::architecture(ARCHITECTURES arch) {
  this->architecture_ = arch;
}


void Header::object_type(OBJECT_TYPES type) {
  this->object_type_ = type;
}


void Header::modes(const std::set<MODES>& m) {
  this->modes_ = m;
}


void Header::entrypoint(uint64_t entrypoint) {
  this->entrypoint_ = entrypoint;
}


void Header::endianness(ENDIANNESS endianness) {
  this->endianness_ = endianness;
}

std::ostream& operator<<(std::ostream& os, const Header& hdr) {

  const std::set<MODES>& m = hdr.modes();
  std::string modes = std::accumulate(
     std::begin(m),
     std::end(m), std::string{},
     [] (const std::string& a, MODES b) {
         return a.empty() ? to_string(b) : a + "-" + to_string(b);
     });
  os << std::hex << std::left;

  std::string bitness = "UNKNOWN";
  if (hdr.is_32()) {
    bitness = "32";
  }

  if (hdr.is_64()) {
    bitness = "64";
  }

  os << std::setw(33) << std::setfill(' ') << "Architecture:" << to_string(hdr.architecture()) << "_" << modes << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Entrypoint:"   << "0x" << hdr.entrypoint()                      << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Object type:"  << to_string(hdr.object_type())                  << std::endl;
  os << std::setw(33) << std::setfill(' ') << "32/64 bits:"   << bitness                                       << std::endl;

  os << std::setw(33) << std::setfill(' ') << "Endianness:"   << to_string(hdr.endianness())                                       << std::endl;
  return os;
}


}
