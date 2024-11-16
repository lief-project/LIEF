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
#include "LIEF/DWARF/types/Subroutine.hpp"
#include "LIEF/rust/DWARF/Type.hpp"
#include "LIEF/rust/DWARF/Parameter.hpp"
#include "LIEF/rust/Iterator.hpp"

class DWARF_types_Subroutine : public DWARF_Type {
  public:

  class it_parameters :
      public ContainerIterator<
        DWARF_Parameter, std::vector<std::unique_ptr<LIEF::dwarf::Parameter>>>
  {
    public:
    using container_t = std::vector<std::unique_ptr<LIEF::dwarf::Parameter>>;
    it_parameters(container_t content)
      : ContainerIterator(std::move(content)) { }
    auto next() { return ContainerIterator::next(); }
  };

  using lief_t = LIEF::dwarf::types::Subroutine;

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }

  auto parameters() const {
    return std::make_unique<it_parameters>(impl().parameters());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
