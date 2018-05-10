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

#include "LIEF/DEX/hash.hpp"
#include "LIEF/DEX.hpp"

namespace LIEF {
namespace DEX {

Hash::~Hash(void) = default;

size_t Hash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::DEX::Hash>(obj);
}


void Hash::visit(const File& file) {
  this->process(file.location());
  this->process(file.header());

  this->process(std::begin(file.classes()), std::end(file.classes()));
  this->process(std::begin(file.methods()), std::end(file.methods()));
  this->process(std::begin(file.strings()), std::end(file.strings()));

}

void Hash::visit(const Header& header) {
  this->process(header.magic());
  this->process(header.checksum());
  this->process(header.signature());
  this->process(header.file_size());
  this->process(header.header_size());
  this->process(header.endian_tag());
  this->process(header.strings());
  this->process(header.link());
  this->process(header.types());
  this->process(header.prototypes());
  this->process(header.fields());
  this->process(header.methods());
  this->process(header.classes());
  this->process(header.data());
}

void Hash::visit(const CodeInfo& code_info) {
}

void Hash::visit(const Class& cls) {

  it_const_methods methods = cls.methods();
  this->process(cls.fullname());
  this->process(cls.source_filename());
  this->process(cls.access_flags());

  this->process(std::begin(methods), std::end(methods));
}

void Hash::visit(const Method& method) {
  this->process(method.name());
  this->process(method.bytecode());
  this->process(method.prototype());
}


void Hash::visit(const Type& type) {
  switch (type.type()) {
    case Type::TYPES::ARRAY:
      {
        this->process(type.dim());
        this->process(type.underlying_array_type());
        break;
      }

    case Type::TYPES::PRIMITIVE:
      {
        this->process(type.primitive());
        break;
      }

    case Type::TYPES::CLASS:
      {
        this->process(type.cls().fullname());
        break;
      }

    case Type::TYPES::UNKNOWN:
    default:
      {
        this->process(Type::TYPES::UNKNOWN);
      }
  }
}

void Hash::visit(const Prototype& type) {
  this->process(type.return_type());
  this->process(
      std::begin(type.parameters_type()),
      std::end(type.parameters_type()));
}

void Hash::visit(const MapItem& item) {
  this->process(item.size());
  this->process(item.offset());
  this->process(item.reserved());
  this->process(item.type());
}

void Hash::visit(const MapList& list) {
  this->process(std::begin(list.items()), std::end(list.items()));
}


} // namespace DEX
} // namespace LIEF

