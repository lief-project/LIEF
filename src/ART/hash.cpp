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

#include "LIEF/ART/hash.hpp"
#include "LIEF/ART.hpp"

namespace LIEF {
namespace ART {

Hash::~Hash(void) = default;

size_t Hash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::ART::Hash>(obj);
}


void Hash::visit(const File& file) {
  process(file.header());
}

void Hash::visit(const Header& header) {
  this->process(header.magic());
  this->process(header.version());
  this->process(header.image_begin());
  this->process(header.image_size());
  this->process(header.oat_checksum());
  this->process(header.oat_file_begin());
  this->process(header.oat_file_end());
  this->process(header.oat_data_begin());
  this->process(header.oat_data_end());
  this->process(header.patch_delta());
  this->process(header.image_roots());
  this->process(header.pointer_size());
  this->process(header.compile_pic());
  this->process(header.nb_sections());
  this->process(header.nb_methods());
  this->process(header.boot_image_begin());
  this->process(header.boot_image_size());
  this->process(header.boot_oat_begin());
  this->process(header.boot_oat_size());
  this->process(header.storage_mode());
  this->process(header.data_size());
}



} // namespace ART
} // namespace LIEF

