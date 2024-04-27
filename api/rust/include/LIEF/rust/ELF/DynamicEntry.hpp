/* Copyright 2024 R. Thomas
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
#pragma once
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class ELF_DynamicEntry : public Mirror<LIEF::ELF::DynamicEntry>{
  friend class ELF_DynamicEntryRpath;
  friend class ELF_DynamicEntryArray;
  friend class ELF_DynamicEntryFlags;
  friend class ELF_DynamicEntryLibrary;
  friend class ELF_DynamicEntryRunPath;
  friend class ELF_DynamicSharedObject;
  public:
  using lief_t = LIEF::ELF::DynamicEntry;
  using Mirror::Mirror;

  uint64_t tag() const { return to_int(get().tag()); }
  uint64_t value() const { return get().value(); }
};
