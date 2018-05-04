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

#include "LIEF/VDEX/File.hpp"
#include "LIEF/VDEX/hash.hpp"
#include "LIEF/json.hpp"

namespace LIEF {
namespace VDEX {

File::File(void) :
  header_{},
  dex_files_{}
{}


const Header& File::header(void) const {
  return this->header_;
}

Header& File::header(void) {
  return const_cast<Header&>(static_cast<const File*>(this)->header());
}


DEX::it_dex_files File::dex_files(void) {
  return this->dex_files_;
}

DEX::it_const_dex_files File::dex_files(void) const {
  return this->dex_files_;
}

dex2dex_info_t File::dex2dex_info(void) const {
  dex2dex_info_t info;
  for (DEX::File* dex_file : this->dex_files_) {
    info.emplace(dex_file, dex_file->dex2dex_info());
  }
  return info;
}

std::string File::dex2dex_json_info(void) {

#if defined(LIEF_JSON_SUPPORT)
  json mapping = json::object();

  for (DEX::File* dex_file : this->dex_files_) {
    json dex2dex = json::parse(dex_file->dex2dex_json_info());
    mapping[dex_file->name()] = dex2dex;
  }

  return mapping.dump();
#else
  return "";
#endif
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


File::~File(void) {
  for (DEX::File* file : this->dex_files_) {
    delete file;
  }
}

std::ostream& operator<<(std::ostream& os, const File& vdex_file) {
  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << vdex_file.header() << std::endl << std::endl;


  os << "DEX Files" << std::endl;
  os << "=========" << std::endl;

  for (const DEX::File& f : vdex_file.dex_files()) {
    os << f << std::endl << std::endl;
  }


  return os;
}

} // Namespace VDEX
} // Namespace LIEF
