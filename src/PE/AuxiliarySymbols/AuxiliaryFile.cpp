/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/PE/AuxiliarySymbols/AuxiliaryFile.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/utils.hpp"

#include "logging.hpp"
namespace LIEF::PE {

std::unique_ptr<AuxiliaryFile>
  AuxiliaryFile::parse(const std::vector<uint8_t>& payload)
{
  SpanStream stream(payload);
  auto file = stream.read_string();
  if (!file) {
    LIEF_WARN("Can't parse AuxiliaryFile.file");
    return std::make_unique<AuxiliaryFile>();
  }
  return std::make_unique<AuxiliaryFile>(std::move(*file));
}
}
