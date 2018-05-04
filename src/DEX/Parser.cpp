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

#include "LIEF/logging++.hpp"
#include "LIEF/filesystem/filesystem.h"

#include "LIEF/DEX/Parser.hpp"
#include "LIEF/DEX/utils.hpp"
#include "LIEF/DEX/Structures.hpp"

#include "Parser.tcc"

namespace LIEF {
namespace DEX {

Parser::~Parser(void) = default;
Parser::Parser(void)  = default;

File* Parser::parse(const std::string& filename) {
  Parser parser{filename};
  return parser.file_;
}

File* Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  return parser.file_;
}


Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  file_{new File{}},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})}
{
  if (not is_dex(data)) {
    LOG(FATAL) << "'" + name + "' is not a DEX";
    delete this->file_;
    this->file_ = nullptr;
    return;
  }

  dex_version_t version = DEX::version(data);
  this->init(name, version);
}

Parser::Parser(const std::string& file) :
  file_{new File{}},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{file})}
{
  if (not is_dex(file)) {
    LOG(FATAL) << "'" + file + "' is not a DEX";
    delete this->file_;
    this->file_ = nullptr;
    return;
  }

  dex_version_t version = DEX::version(file);
  this->init(filesystem::path(file).filename(), version);
}


void Parser::init(const std::string& name, dex_version_t version) {
  LOG(DEBUG) << "Parsing file: " << name << std::endl;

  if (version == DEX_35::dex_version) {
    return this->parse_file<DEX35>();
  }

  if (version == DEX_37::dex_version) {
    return this->parse_file<DEX37>();
  }

  if (version == DEX_38::dex_version) {
    return this->parse_file<DEX38>();
  }

}

void Parser::resolve_inheritance(void) {
  VLOG(VDEBUG) << "Resolving inheritance relationship for "
               << std::dec << this->inheritance_.size() << " classes";

  for (const std::pair<std::string, Class*>& p : this->inheritance_) {
    const std::string& parent_name = p.first;
    Class* child = p.second;

    auto&& it_inner_class = this->file_->classes_.find(parent_name);
    if (it_inner_class == std::end(this->file_->classes_)) {
      Class* external_class = new Class{parent_name};
      this->file_->classes_.emplace(parent_name, external_class);
      child->parent_ = external_class;
    } else {
      child->parent_ = it_inner_class->second;
    }
  }
}

void Parser::resolve_external_methods(void) {
  VLOG(VDEBUG) << "Resolving external methods for "
               << std::dec << this->class_method_map_.size() << " methods";

  for (const std::pair<std::string, Method*>& p : this->class_method_map_) {
    const std::string& clazz = p.first;
    Method* method = p.second;

    auto&& it_inner_class = this->file_->classes_.find(clazz);
    if (it_inner_class == std::end(this->file_->classes_)) {
      Class* cls = new Class{clazz};
      cls->methods_.push_back(method);
      method->parent_ = cls;
      this->file_->classes_.emplace(clazz, cls);
    } else {
      Class* cls = it_inner_class->second;
      method->parent_ = cls;
      cls->methods_.push_back(method);
    }

  }
}

void Parser::resolve_types(void) {
  for (auto&& p : this->class_type_map_) {
    if(this->file_->has_class(p.first)) {
      p.second->underlying_array_type().cls_ = &this->file_->get_class(p.first);
    } else {
      Class* cls = new Class{p.first};
      this->file_->classes_.emplace(p.first, cls);
      p.second->underlying_array_type().cls_ = cls;
    }
  }
}



} // namespace DEX
} // namespace LIEF
