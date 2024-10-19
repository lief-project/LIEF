/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/DyldSharedCache/SubCache.hpp"
#include "LIEF/rust/Mirror.hpp"

class dsc_DyldSharedCache;

class dsc_SubCache : private Mirror<LIEF::dsc::SubCache> {
  public:
  using lief_t = LIEF::dsc::SubCache;
  using Mirror::Mirror;

  auto vm_offset() const { return get().vm_offset(); }
  auto suffix() const { return get().suffix(); }
  auto uuid() const { return details::make_vector(get().uuid()); }
  LIEF_API std::unique_ptr<dsc_DyldSharedCache> cache() const;
};
