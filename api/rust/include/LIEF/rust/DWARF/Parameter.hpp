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
#include "LIEF/DWARF/Parameter.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/DWARF/Type.hpp"

class DWARF_Parameter : public Mirror<LIEF::dwarf::Parameter> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Parameter;

  auto name() const { return get().name(); }

  auto get_type() const {
    return details::try_unique<DWARF_Type>(get().type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};

class DWARF_parameters_Formal : public DWARF_Parameter {
  public:
  using lief_t = LIEF::dwarf::parameters::Formal;

  static bool classof(const DWARF_Parameter& type) {
    return lief_t::classof(&type.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class DWARF_parameters_TemplateValue : public DWARF_Parameter {
  public:
  using lief_t = LIEF::dwarf::parameters::TemplateValue;

  static bool classof(const DWARF_Parameter& type) {
    return lief_t::classof(&type.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class DWARF_parameters_TemplateType : public DWARF_Parameter {
  public:
  using lief_t = LIEF::dwarf::parameters::TemplateType;

  static bool classof(const DWARF_Parameter& type) {
    return lief_t::classof(&type.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
