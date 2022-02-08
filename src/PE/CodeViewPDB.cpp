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
#include <utility>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/CodeViewPDB.hpp"

namespace LIEF {
namespace PE {

CodeViewPDB::CodeViewPDB(const CodeViewPDB&) = default;
CodeViewPDB& CodeViewPDB::operator=(const CodeViewPDB&) = default;
CodeViewPDB::~CodeViewPDB() = default;

CodeViewPDB::CodeViewPDB() :
  signature_{
    {
      0, 0, 0, 0,
      0, 0, 0, 0,
      0, 0, 0, 0,
      0, 0, 0, 0,
    }
  },
  age_{0}
{}


CodeViewPDB::CodeViewPDB(CODE_VIEW_SIGNATURES cv_signature, signature_t sig,
                         uint32_t age, std::string filename) :
  CodeView(cv_signature),
  signature_(sig),
  age_(age),
  filename_(std::move(filename))
{}


CodeViewPDB CodeViewPDB::from_pdb70(signature_t sig, uint32_t age, const std::string& filename) {
  return {CODE_VIEW_SIGNATURES::CVS_PDB_70, sig, age, filename};
}
CodeViewPDB CodeViewPDB::from_pdb20(uint32_t signature, uint32_t age, const std::string& filename) {
  CodeViewPDB::signature_t sig = {{
    static_cast<uint8_t>(signature >> 0),
    static_cast<uint8_t>(signature >> 8),
    static_cast<uint8_t>(signature >> 16),
    static_cast<uint8_t>(signature >> 24),
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  }};
  return {CODE_VIEW_SIGNATURES::CVS_PDB_20, sig, age, filename};
}


CodeViewPDB* CodeViewPDB::clone() const {
  return new CodeViewPDB{*this};
}



CodeViewPDB::signature_t CodeViewPDB::signature() const {
  return signature_;
}

uint32_t CodeViewPDB::age() const {
  return age_;
}

const std::string& CodeViewPDB::filename() const {
  return filename_;
}


void CodeViewPDB::signature(uint32_t signature) {
  this->signature({{
    static_cast<uint8_t>(signature >> 0),
    static_cast<uint8_t>(signature >> 8),
    static_cast<uint8_t>(signature >> 16),
    static_cast<uint8_t>(signature >> 24),
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  }});

}

void CodeViewPDB::signature(CodeViewPDB::signature_t signature) {
  signature_ = signature;
}

void CodeViewPDB::age(uint32_t age) {
  age_ = age;
}

void CodeViewPDB::filename(const std::string& filename) {
  filename_ = filename;
}



void CodeViewPDB::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool CodeViewPDB::operator==(const CodeViewPDB& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CodeViewPDB::operator!=(const CodeViewPDB& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const CodeViewPDB& entry) {
  static constexpr size_t WIDTH = 22;
  const CodeViewPDB::signature_t sig = entry.signature();
  std::string sig_str = std::accumulate(
     std::begin(sig),
     std::end(sig), std::string{},
     [] (const std::string& a, uint8_t byte) {
      std::stringstream ss;
      ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint32_t>(byte);
      return a.empty() ? ss.str() : a + " " + ss.str();
     });


  os << std::hex;
  os << std::left;
  os << std::setfill(' ');

  os << std::setw(WIDTH) << "Code View Signature:" << to_string(entry.cv_signature())  << std::endl;
  os << std::setw(WIDTH) << "Signature:"           << sig_str                       << std::endl;
  os << std::setw(WIDTH) << "Age:"                 << std::dec << entry.age()       << std::endl;
  os << std::setw(WIDTH) << "Path:"                << entry.filename()              << std::endl;
  return os;
}

} // namespace PE
} // namespace LIEF
