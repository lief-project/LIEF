/* Copyright 2024 - 2025 R. Thomas
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

#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicRelocationBase.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicRelocationV1.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicRelocationV2.hpp"

#include "LIEF/rust/PE/LoadConfiguration/DynamicRelocation/DynamicFixup.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_DynamicRelocation : public Mirror<LIEF::PE::DynamicRelocation> {
  public:
  using lief_t = LIEF::PE::DynamicRelocation;
  using Mirror::Mirror;

  auto version() const { return get().version(); }
  auto symbol() const { return get().symbol(); }

  auto fixups() const {
    return details::try_unique<PE_DynamicFixup>(get().fixups());
  }

  std::string to_string() const {
    return get().to_string();
  }
};

class PE_DynamicRelocationV1 : public PE_DynamicRelocation {
  public:
  using lief_t = LIEF::PE::DynamicRelocationV1;

  static bool classof(const PE_DynamicRelocation& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_DynamicRelocationV2 : public PE_DynamicRelocation {
  public:
  using lief_t = LIEF::PE::DynamicRelocationV2;

  static bool classof(const PE_DynamicRelocation& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
