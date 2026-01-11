/* Copyright 2022 - 2026 R. Thomas
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
#include <algorithm>
#include <LIEF/range.hpp>
#include <LIEF/DWARF/editor/Function.hpp>
#include "LIEF/rust/Mirror.hpp"

#include "LIEF/rust/DWARF/editor/Type.hpp"
#include "LIEF/rust/DWARF/editor/Variable.hpp"

class DWARF_editor_Function_Range {
  public:
  uint64_t start = 0;
  uint64_t end = 0;
};

class DWARF_editor_Function_Parameter : public Mirror<LIEF::dwarf::editor::Function::Parameter> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::Function::Parameter;

  void assign_register_by_name(std::string name) {
    get().assign_register(name);
  }

  void assign_register_by_id(uint64_t id) {
    get().assign_register(id);
  }
};

class DWARF_editor_Function_LexicalBlock : public Mirror<LIEF::dwarf::editor::Function::LexicalBlock> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::Function::LexicalBlock;

  auto add_block(uint64_t start, uint64_t end) {
    return details::try_unique<DWARF_editor_Function_LexicalBlock>(
      get().add_block(start, end)
    );
  }

  auto add_block_from_range(const std::vector<DWARF_editor_Function_Range>& ranges) {
    std::vector<LIEF::dwarf::editor::Function::range_t> conv_ranges;
    conv_ranges.reserve(ranges.size());
    std::transform(ranges.begin(), ranges.end(), std::back_inserter(conv_ranges),
      [] (const DWARF_editor_Function_Range& R) {
        return LIEF::dwarf::editor::Function::range_t{R.start, R.end};
      });

    return details::try_unique<DWARF_editor_Function_LexicalBlock>(
      get().add_block(conv_ranges)
    );
  }

  auto add_name(std::string name) {
    get().add_name(name);
  }

  auto add_description(std::string name) {
    get().add_description(name);
  }
};

class DWARF_editor_Function_Label : public Mirror<LIEF::dwarf::editor::Function::Label> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::Function::Label;
};

class DWARF_editor_Function : public Mirror<LIEF::dwarf::editor::Function> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::Function;

  auto set_address(uint64_t addr) { get().set_address(addr); }
  auto set_low_high(uint64_t low, uint64_t high) { get().set_low_high(low, high); }
  auto set_ranges(const std::vector<DWARF_editor_Function_Range>& ranges) {
    std::vector<lief_t::range_t> conv_ranges;
    conv_ranges.reserve(ranges.size());
    std::transform(ranges.begin(), ranges.end(), std::back_inserter(conv_ranges),
      [] (const DWARF_editor_Function_Range& R) {
        return lief_t::range_t{R.start, R.end};
      });
    return conv_ranges;
  }
  auto set_external() { get().set_external(); }

  auto set_return_type(const DWARF_editor_Type& ty) {
    get().set_return_type(ty.get());
  }

  auto add_parameter(std::string name, const DWARF_editor_Type& ty) {
    return details::try_unique<DWARF_editor_Function_Parameter>(
      get().add_parameter(name, ty.get())
    );
  }

  auto create_stack_variable(std::string name) {
    return details::try_unique<DWARF_editor_Variable>(
      get().create_stack_variable(name)
    );
  }

  auto add_lexical_block(uint64_t start, uint64_t end) {
    return details::try_unique<DWARF_editor_Function_LexicalBlock>(
      get().add_lexical_block(start, end)
    );
  }

  auto add_label(uint64_t addr, std::string label) {
    return details::try_unique<DWARF_editor_Function_Label>(
      get().add_label(addr, label)
    );
  }

  auto add_description(std::string desc) { get().add_description(desc); }
};
