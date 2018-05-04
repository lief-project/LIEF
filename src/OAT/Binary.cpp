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
#include <fstream>

#include "LIEF/OAT/Binary.hpp"
#include "LIEF/OAT/hash.hpp"
#include "LIEF/logging++.hpp"
#include "LIEF/json.hpp"

#include "LIEF/VDEX.hpp"

namespace LIEF {
namespace OAT {

Binary::Binary(void) :
  ELF::Binary{},
  header_{},
  dex_files_{},
  oat_dex_files_{},
  classes_{}
{}


const Header& Binary::header(void) const {
  return this->header_;
}

Header& Binary::header(void) {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}

DEX::it_dex_files Binary::dex_files(void) {
  return this->dex_files_;
}

DEX::it_const_dex_files Binary::dex_files(void) const {
  return this->dex_files_;
}

it_dex_files Binary::oat_dex_files(void) {
  return this->oat_dex_files_;
}
it_const_dex_files Binary::oat_dex_files(void) const {
  return this->oat_dex_files_;
}


it_const_classes Binary::classes(void) const {
  classes_list_t classes;
  classes.reserve(this->classes_.size());

  std::transform(
      std::begin(this->classes_), std::end(this->classes_),
      std::back_inserter(classes),
      [] (std::pair<std::string, Class*> it) {
        return it.second;
      });
  return classes;
}

it_classes Binary::classes(void) {
  classes_list_t classes;
  classes.reserve(this->classes_.size());

  std::transform(
      std::begin(this->classes_), std::end(this->classes_),
      std::back_inserter(classes),
      [] (std::pair<std::string, Class*> it) {
        return it.second;
      });
  return classes;
}

bool Binary::has_class(const std::string& class_name) const {
  return this->classes_.find(DEX::Class::fullname_normalized(class_name)) != std::end(this->classes_);
}

const Class& Binary::get_class(const std::string& class_name) const {
  if (not this->has_class(class_name)) {
    throw not_found(class_name);
  }
  return *(this->classes_.find(DEX::Class::fullname_normalized(class_name))->second);
}

Class& Binary::get_class(const std::string& class_name) {
  return const_cast<Class&>(static_cast<const Binary*>(this)->get_class(class_name));
}


const Class& Binary::get_class(size_t index) const {
  if (index >= this->classes_.size()) {
    throw not_found("Can't find class at index " + std::to_string(index));
  }

  auto&& it = std::find_if(
      std::begin(this->classes_),
      std::end(this->classes_),
      [index] (const std::pair<std::string, Class*>& p) {
        return p.second->index() == index;
      });

  if (it != std::end(this->classes_)) {
    return *it->second;
  }

  throw not_found("Can't find class at index " + std::to_string(index));
}

Class& Binary::get_class(size_t index) {
  return const_cast<Class&>(static_cast<const Binary*>(this)->get_class(index));
}

it_const_methods Binary::methods(void) const {
  return this->methods_;
}

it_methods Binary::methods(void) {
  return this->methods_;
}

dex2dex_info_t Binary::dex2dex_info(void) const {
  dex2dex_info_t info;
  for (DEX::File* dex_file : this->dex_files_) {
    info.emplace(dex_file, dex_file->dex2dex_info());
  }
  return info;
}

std::string Binary::dex2dex_json_info(void) {

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

void Binary::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Binary::operator==(const Binary& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Binary::operator!=(const Binary& rhs) const {
  return not (*this == rhs);
}

Binary::~Binary(void) {

  for (DexFile* file : this->oat_dex_files_) {
    delete file;
  }

  for (const std::pair<std::string, Class*>& p : this->classes_) {
    delete p.second;
  }

  for (Method* mtd : this->methods_) {
    delete mtd;
  }

  if (not this->vdex_) {
    // DEX are owned by us
    for (DEX::File* file : this->dex_files_) {
      delete file;
    }
  } else {
    // DEX file are owned by VDEX
    delete this->vdex_;
  }
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

  std::cout << "Number of classes: " << std::dec << binary.classes().size() << std::endl;
  std::cout << "Number of methods: " << std::dec << binary.methods().size() << std::endl;


  return os;
}


}
}
