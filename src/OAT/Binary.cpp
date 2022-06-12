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
#include <fstream>

#include "LIEF/VDEX.hpp"
#include "LIEF/VDEX/File.hpp"
#include "LIEF/DEX/File.hpp"

#include "LIEF/OAT/Binary.hpp"
#include "LIEF/OAT/hash.hpp"
#include "logging.hpp"

#if defined(LIEF_JSON_SUPPORT)
#include "visitors/json.hpp"
#endif


namespace LIEF {
namespace OAT {

Binary::Binary() = default;
Binary::~Binary() = default;

const Header& Binary::header() const {
  return header_;
}

Header& Binary::header() {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}

Binary::it_dex_files Binary::dex_files() {
  if (vdex_ != nullptr) {
    return vdex_->dex_files_;
  }
  return dex_files_;
}

Binary::it_const_dex_files Binary::dex_files() const {
  if (vdex_ != nullptr) {
    return vdex_->dex_files_;
  }
  return dex_files_;
}

Binary::it_oat_dex_files Binary::oat_dex_files() {
  return oat_dex_files_;
}

Binary::it_const_oat_dex_files Binary::oat_dex_files() const {
  return oat_dex_files_;
}


Binary::it_const_classes Binary::classes() const {
  return classes_list_;
}

Binary::it_classes Binary::classes() {
  return classes_list_;
}

bool Binary::has_class(const std::string& class_name) const {
  return classes_.find(DEX::Class::fullname_normalized(class_name)) != std::end(classes_);
}

const Class* Binary::get_class(const std::string& class_name) const {
  auto it = classes_.find(DEX::Class::fullname_normalized(class_name));
  if (it == std::end(classes_)) {
    return nullptr;
  }
  return it->second;
}

Class* Binary::get_class(const std::string& class_name) {
  return const_cast<Class*>(static_cast<const Binary*>(this)->get_class(class_name));
}


const Class* Binary::get_class(size_t index) const {
  if (index >= classes_.size()) {
    return nullptr;
  }

  const auto it = std::find_if(std::begin(classes_), std::end(classes_),
      [index] (const std::pair<std::string, Class*>& p) {
        return p.second->index() == index;
      });

  if (it == std::end(classes_)) {
    return nullptr;
  }
  return it->second;
}

Class* Binary::get_class(size_t index) {
  return const_cast<Class*>(static_cast<const Binary*>(this)->get_class(index));
}

Binary::it_const_methods Binary::methods() const {
  return methods_;
}

Binary::it_methods Binary::methods() {
  return methods_;
}

Binary::dex2dex_info_t Binary::dex2dex_info() const {
  dex2dex_info_t info;

  for (const DEX::File& dex_file : dex_files()) {
    info.emplace(&dex_file, dex_file.dex2dex_info());
  }
  return info;
}

std::string Binary::dex2dex_json_info() {

#if defined(LIEF_JSON_SUPPORT)
  json mapping = json::object();

  for (const DEX::File& dex_file : dex_files()) {
    json dex2dex = json::parse(dex_file.dex2dex_json_info());
    mapping[dex_file.name()] = dex2dex;
  }

  return mapping.dump();
#else
  return "";
#endif

}

void Binary::add_class(std::unique_ptr<Class> cls) {
  classes_.emplace(cls->fullname(), cls.get());
  classes_list_.push_back(std::move(cls));
}

void Binary::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Binary::operator==(const Binary& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Binary::operator!=(const Binary& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Binary& binary) {

  os << "Header" << std::endl;
  os << "======" << std::endl;
  os << binary.header() << std::endl;

  if (binary.oat_dex_files().size() > 0) {
    os << "Dex Files" << std::endl;
    os << "=========" << std::endl;

    for (const DexFile& dex : binary.oat_dex_files()) {
      os << dex << std::endl;
    }
  }

  os << "Number of classes: " << std::dec << binary.classes().size() << std::endl;
  os << "Number of methods: " << std::dec << binary.methods().size() << std::endl;


  return os;
}


}
}
