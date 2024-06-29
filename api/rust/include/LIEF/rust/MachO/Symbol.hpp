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
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/rust/Abstract/Symbol.hpp"
#include "LIEF/rust/MachO/Dylib.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/visibility.h"

class MachO_ExportInfo;
class MachO_BindingInfo;

class MachO_Symbol : public AbstractSymbol {
  using lief_t = LIEF::MachO::Symbol;
  public:
  MachO_Symbol(const lief_t& sym) : AbstractSymbol(sym) {}

  uint8_t get_type() const { return impl().raw_type(); }
  uint8_t numberof_sections() const { return impl().numberof_sections(); };
  uint16_t description() const { return impl().description(); };
  auto origin() const { return to_int(impl().origin()); };
  auto category() const { return to_int(impl().category()); };
  bool is_external() const { return impl().is_external(); };

  LIEF_API std::unique_ptr<MachO_ExportInfo> export_info() const;
  LIEF_API std::unique_ptr<MachO_BindingInfo> binding_info() const;

  auto library() const {
    return details::try_unique<MachO_Dylib>(impl().library());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
