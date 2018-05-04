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

#include "LIEF/VDEX/hash.hpp"
#include "LIEF/VDEX.hpp"
#include "LIEF/DEX/hash.hpp"

namespace LIEF {
namespace VDEX {

Hash::~Hash(void) = default;

size_t Hash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::VDEX::Hash>(obj);
}


void Hash::visit(const File& file) {
  this->process(file.header());
  for (const DEX::File& dexfile : file.dex_files()) {
    this->process(DEX::Hash::hash(dexfile));
  }
}

void Hash::visit(const Header& header) {
  this->process(header.magic());
  this->process(header.version());
  this->process(header.nb_dex_files());
  this->process(header.dex_size());
  this->process(header.verifier_deps_size());
  this->process(header.quickening_info_size());
}



} // namespace VDEX
} // namespace LIEF

