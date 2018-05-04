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

#include "LIEF/exception.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/utils.hpp"

#include "LIEF/PE/resources/ResourceVersion.hpp"

namespace LIEF {
namespace PE {

ResourceVersion::ResourceVersion(const ResourceVersion&) = default;
ResourceVersion& ResourceVersion::operator=(const ResourceVersion&) = default;
ResourceVersion::~ResourceVersion(void) = default;


ResourceVersion::ResourceVersion(void) :
  type_{0},
  key_{u8tou16("VS_VERSION_INFO")},
  has_fixed_file_info_{false},
  fixed_file_info_{},
  has_string_file_info_{false},
  string_file_info_{},
  has_var_file_info_{false},
  var_file_info_{}
{}


uint16_t ResourceVersion::type(void) const {
  return this->type_;
}

const std::u16string& ResourceVersion::key(void) const {
  return this->key_;
}

bool ResourceVersion::has_fixed_file_info(void) const {
  return this->has_fixed_file_info_;
}

bool ResourceVersion::has_string_file_info(void) const {
  return this->has_string_file_info_;
}

bool ResourceVersion::has_var_file_info(void) const {
  return this->has_var_file_info_;
}

const ResourceFixedFileInfo& ResourceVersion::fixed_file_info(void) const {
  if (not this->has_fixed_file_info()) {
    throw not_found("Fixed file info is not present in the current resource");
  }
  return this->fixed_file_info_;
}

ResourceFixedFileInfo& ResourceVersion::fixed_file_info(void) {
  return const_cast<ResourceFixedFileInfo&>(static_cast<const ResourceVersion*>(this)->fixed_file_info());
}

const ResourceStringFileInfo& ResourceVersion::string_file_info(void) const {
  if (not this->has_string_file_info()) {
    throw not_found("String file info is not present in the current resource");
  }
  return this->string_file_info_;
}

ResourceStringFileInfo& ResourceVersion::string_file_info(void) {
  return const_cast<ResourceStringFileInfo&>(static_cast<const ResourceVersion*>(this)->string_file_info());
}

const ResourceVarFileInfo& ResourceVersion::var_file_info(void) const {
  if (not this->has_var_file_info()) {
    throw not_found("Var file info is not present in the current resource");
  }
  return this->var_file_info_;
}

ResourceVarFileInfo& ResourceVersion::var_file_info(void) {
  return const_cast<ResourceVarFileInfo&>(static_cast<const ResourceVersion*>(this)->var_file_info());
}


void ResourceVersion::type(uint16_t type) {
  this->type_ = type;
}

void ResourceVersion::key(const std::u16string& key) {
  this->key_ = key;
}

void ResourceVersion::key(const std::string& key) {
  this->key(u8tou16(key));
}

void ResourceVersion::fixed_file_info(const ResourceFixedFileInfo& fixed_file_info) {
  this->fixed_file_info_ = fixed_file_info;
  this->has_fixed_file_info_ = true;
}

void ResourceVersion::remove_fixed_file_info(void) {
  this->has_fixed_file_info_ = false;
}

void ResourceVersion::string_file_info(const ResourceStringFileInfo& string_file_info) {
  this->string_file_info_ = string_file_info;
  this->has_string_file_info_ = true;
}

void ResourceVersion::remove_string_file_info(void) {
  this->has_string_file_info_ = false;
}

void ResourceVersion::var_file_info(const ResourceVarFileInfo& var_file_info) {
  this->var_file_info_ = var_file_info;
  this->has_var_file_info_ = true;
}

void ResourceVersion::remove_var_file_info(void) {
  this->has_var_file_info_ = false;
}


void ResourceVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ResourceVersion::operator==(const ResourceVersion& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceVersion::operator!=(const ResourceVersion& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceVersion& version) {
  os << std::hex << std::left;
  os << std::setw(6) << std::setfill(' ') << "type:" << version.type()         << std::endl;
  os << std::setw(6) << std::setfill(' ') << "key:"  << u16tou8(version.key()) << std::endl << std::endl;

  if (version.has_fixed_file_info()) {
    os << "Fixed file info" << std::endl;
    os << "===============" << std::endl;
    os << version.fixed_file_info();
    os << std::endl;
  }


  if (version.has_string_file_info()) {
    os << "String file info" << std::endl;
    os << "================" << std::endl;
    os << version.string_file_info();
    os << std::endl;
  }

  if (version.has_var_file_info()) {
    os << "Var file info" << std::endl;
    os << "=============" << std::endl;
    os << version.var_file_info();
    os << std::endl;
  }
  return os;
}


}
}
