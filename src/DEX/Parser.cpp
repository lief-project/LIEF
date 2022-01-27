/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include <memory>

#include "logging.hpp"

#include "LIEF/DEX/Parser.hpp"
#include "LIEF/DEX/utils.hpp"
#include "LIEF/DEX/Structures.hpp"

#include "filesystem/filesystem.h"

#include "Parser.tcc"

namespace LIEF {
namespace DEX {

Parser::~Parser() = default;
Parser::Parser()  = default;

std::unique_ptr<File> Parser::parse(const std::string& filename) {
  Parser parser{filename};
  return std::unique_ptr<File>{parser.file_};
}

std::unique_ptr<File> Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  return std::unique_ptr<File>{parser.file_};
}


Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  file_{new File{}},
  stream_{std::make_unique<VectorStream>(data)}
{
  if (!is_dex(data)) {
    LIEF_ERR("'{}' is not a DEX File", name);
    delete file_;
    file_ = nullptr;
    return;
  }

  dex_version_t version = DEX::version(data);
  init(name, version);
}

Parser::Parser(const std::string& file) :
  file_{new File{}},
  stream_{std::make_unique<VectorStream>(file)}
{
  if (!is_dex(file)) {
    LIEF_ERR("'{}' is not a DEX File", file);
    delete file_;
    file_ = nullptr;
    return;
  }

  dex_version_t version = DEX::version(file);
  init(filesystem::path(file).filename(), version);
}


void Parser::init(const std::string& name, dex_version_t version) {
  LIEF_DEBUG("Parsing file: {}", name);

  if (version == DEX_35::dex_version) {
    return parse_file<DEX35>();
  }

  if (version == DEX_37::dex_version) {
    return parse_file<DEX37>();
  }

  if (version == DEX_38::dex_version) {
    return parse_file<DEX38>();
  }

  if (version == DEX_39::dex_version) {
    return parse_file<DEX39>();
  }

}

void Parser::resolve_inheritance() {
  LIEF_DEBUG("Resolving inheritance relationship for #{:d} classes", inheritance_.size());

  for (const std::pair<const std::string, Class*>& p : inheritance_) {
    const std::string& parent_name = p.first;
    Class* child = p.second;

    const auto it_inner_class = file_->classes_.find(parent_name);
    if (it_inner_class == std::end(file_->classes_)) {
      auto* external_class = new Class{parent_name};
      file_->classes_.emplace(parent_name, external_class);
      child->parent_ = external_class;
    } else {
      child->parent_ = it_inner_class->second;
    }
  }
}

void Parser::resolve_external_methods() {
  LIEF_DEBUG("Resolving external methods for #{:d} methods", class_method_map_.size());

  for (const std::pair<const std::string, Method*>& p : class_method_map_) {
    const std::string& clazz = p.first;
    Method* method = p.second;

    const auto it_inner_class = file_->classes_.find(clazz);
    if (it_inner_class == std::end(file_->classes_)) {
      auto* cls = new Class{clazz};
      cls->methods_.push_back(method);
      method->parent_ = cls;
      file_->classes_.emplace(clazz, cls);
    } else {
      Class* cls = it_inner_class->second;
      method->parent_ = cls;
      cls->methods_.push_back(method);
    }

  }
}

void Parser::resolve_external_fields() {
  LIEF_DEBUG("Resolving external fields for #{:d} fields", class_field_map_.size());

  for (const std::pair<const std::string, Field*>& p : class_field_map_) {
    const std::string& clazz = p.first;
    Field* field = p.second;

    const auto it_inner_class = file_->classes_.find(clazz);
    if (it_inner_class == std::end(file_->classes_)) {
      auto* cls = new Class{clazz};
      cls->fields_.push_back(field);
      field->parent_ = cls;
      file_->classes_.emplace(clazz, cls);
    } else {
      Class* cls = it_inner_class->second;
      field->parent_ = cls;
      cls->fields_.push_back(field);
    }

  }
}

void Parser::resolve_types() {
  for (const auto& p : class_type_map_) {
    if(file_->has_class(p.first)) {
      p.second->underlying_array_type().cls_ = &file_->get_class(p.first);
    } else {
      auto* cls = new Class{p.first};
      file_->classes_.emplace(p.first, cls);
      p.second->underlying_array_type().cls_ = cls;
    }
  }
}



} // namespace DEX
} // namespace LIEF
