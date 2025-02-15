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

#include "LIEF/PE/AuxiliarySymbols/AuxiliaryFunctionDefinition.hpp"
#include "LIEF/rust/PE/AuxiliarySymbol.hpp"

class PE_AuxiliaryFunctionDefinition : public PE_AuxiliarySymbol {
  public:
  using lief_t = LIEF::PE::AuxiliaryFunctionDefinition;
  PE_AuxiliaryFunctionDefinition(const lief_t& obj) : PE_AuxiliarySymbol(obj) {}

  auto tag_index() const { return impl().tag_index(); }
  auto total_size() const { return impl().total_size(); }
  auto ptr_to_line_number() const { return impl().ptr_to_line_number(); }
  auto ptr_to_next_func() const { return impl().ptr_to_next_func(); }
  auto padding() const { return impl().padding(); }

  static bool classof(const PE_AuxiliarySymbol& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
