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

#include "LIEF/exception.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/resources/ResourceVersion.hpp"
#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"

namespace LIEF {
namespace PE {

ResourceVersion::~ResourceVersion() = default;
ResourceVersion::ResourceVersion(const ResourceVersion& copy) :
  LIEF::Object{copy},
  type_{copy.type_},
  key_{copy.key_}
{
  if (copy.fixed_file_info_ != nullptr) {
    fixed_file_info_ = std::make_unique<ResourceFixedFileInfo>(*copy.fixed_file_info_);
  }

  if (copy.string_file_info_ != nullptr) {
    string_file_info_ = std::make_unique<ResourceStringFileInfo>(*copy.string_file_info_);
  }

  if (copy.var_file_info_ != nullptr) {
    var_file_info_ = std::make_unique<ResourceVarFileInfo>(*copy.var_file_info_);
  }
}

ResourceVersion& ResourceVersion::operator=(const ResourceVersion& other) {
  if (this != &other) {
    type_ = other.type_;
    key_  = other.key_;

    if (other.fixed_file_info_ != nullptr) {
      fixed_file_info_ = std::make_unique<ResourceFixedFileInfo>(*other.fixed_file_info_);
    }

    if (other.string_file_info_ != nullptr) {
      string_file_info_ = std::make_unique<ResourceStringFileInfo>(*other.string_file_info_);
    }

    if (other.var_file_info_ != nullptr) {
      var_file_info_ = std::make_unique<ResourceVarFileInfo>(*other.var_file_info_);
    }
  }
  return *this;
}

ResourceVersion::ResourceVersion() :
  type_{0},
  key_{u8tou16("VS_VERSION_INFO")}
{}

uint16_t ResourceVersion::type() const {
  return type_;
}

const std::u16string& ResourceVersion::key() const {
  return key_;
}

bool ResourceVersion::has_fixed_file_info() const {
  return fixed_file_info_ != nullptr;
}

bool ResourceVersion::has_string_file_info() const {
  return string_file_info_ != nullptr;
}

bool ResourceVersion::has_var_file_info() const {
  return var_file_info_ != nullptr;
}

const ResourceFixedFileInfo* ResourceVersion::fixed_file_info() const {
  return fixed_file_info_.get();
}

ResourceFixedFileInfo* ResourceVersion::fixed_file_info() {
  return const_cast<ResourceFixedFileInfo*>(static_cast<const ResourceVersion*>(this)->fixed_file_info());
}

const ResourceStringFileInfo* ResourceVersion::string_file_info() const {
  return string_file_info_.get();
}

ResourceStringFileInfo* ResourceVersion::string_file_info() {
  return const_cast<ResourceStringFileInfo*>(static_cast<const ResourceVersion*>(this)->string_file_info());
}

const ResourceVarFileInfo* ResourceVersion::var_file_info() const {
  return var_file_info_.get();
}

ResourceVarFileInfo* ResourceVersion::var_file_info() {
  return const_cast<ResourceVarFileInfo*>(static_cast<const ResourceVersion*>(this)->var_file_info());
}

void ResourceVersion::type(uint16_t type) {
  type_ = type;
}

void ResourceVersion::key(const std::u16string& key) {
  key_ = key;
}

void ResourceVersion::key(const std::string& key) {
  this->key(u8tou16(key));
}

void ResourceVersion::fixed_file_info(const ResourceFixedFileInfo& fixed_file_info) {
  fixed_file_info_ = std::make_unique<ResourceFixedFileInfo>(fixed_file_info);
}

void ResourceVersion::remove_fixed_file_info() {
  fixed_file_info_.reset(nullptr);
}

void ResourceVersion::string_file_info(const ResourceStringFileInfo& string_file_info) {
  string_file_info_ = std::make_unique<ResourceStringFileInfo>(string_file_info);
}

void ResourceVersion::remove_string_file_info() {
  string_file_info_.reset(nullptr);
}

void ResourceVersion::var_file_info(const ResourceVarFileInfo& var_file_info) {
  var_file_info_ = std::make_unique<ResourceVarFileInfo>(var_file_info);
}

void ResourceVersion::remove_var_file_info() {
  var_file_info_.reset(nullptr);
}

void ResourceVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ResourceVersion::operator==(const ResourceVersion& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceVersion::operator!=(const ResourceVersion& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceVersion& version) {
  os << std::hex << std::left;
  os << std::setw(6) << std::setfill(' ') << "type:" << version.type()         << std::endl;
  os << std::setw(6) << std::setfill(' ') << "key:"  << u16tou8(version.key()) << std::endl << std::endl;

  if (const auto* fixed_file_info = version.fixed_file_info()) {
    os << "Fixed file info" << std::endl;
    os << "===============" << std::endl;
    os << *fixed_file_info;
    os << std::endl;
  }


  if (const auto* string_file_info = version.string_file_info()) {
    os << "String file info" << std::endl;
    os << "================" << std::endl;
    os << *string_file_info;
    os << std::endl;
  }

  if (const auto* var_file_info = version.var_file_info()) {
    os << "Var file info" << std::endl;
    os << "=============" << std::endl;
    os << *var_file_info;
    os << std::endl;
  }
  return os;
}


}
}
