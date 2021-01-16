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

#include "LIEF/Abstract/hash.hpp"
#include "LIEF/Abstract.hpp"

#include "Object.tcc"

namespace LIEF {

AbstractHash::~AbstractHash(void) = default;

size_t AbstractHash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::AbstractHash>(obj);
}


void AbstractHash::visit(const Binary& binary) {
  this->process(binary.format());
  this->process(binary.header());
  this->process(std::begin(binary.symbols()), std::end(binary.symbols()));
  this->process(std::begin(binary.sections()), std::end(binary.sections()));
  this->process(std::begin(binary.relocations()), std::end(binary.relocations()));
}

void AbstractHash::visit(const Header& header) {
  this->process(header.architecture());
  this->process(header.modes());
  this->process(header.object_type());
  this->process(header.entrypoint());
  this->process(header.endianness());
}

void AbstractHash::visit(const Section& section) {
  this->process(section.name());
  this->process(section.offset());
  this->process(section.size());
  this->process(section.virtual_address());
}

void AbstractHash::visit(const Symbol& symbol) {
  this->process(symbol.name());
  this->process(symbol.value());
  this->process(symbol.size());
}

void AbstractHash::visit(const Relocation& relocation) {
  this->process(relocation.address());
  this->process(relocation.size());
}

void AbstractHash::visit(const Function& function) {
  this->visit(*function.as<LIEF::Symbol>());
  Function::flags_list_t flags = function.flags();
  this->process(std::begin(flags), std::end(flags));
}


} // namespace LIEF

