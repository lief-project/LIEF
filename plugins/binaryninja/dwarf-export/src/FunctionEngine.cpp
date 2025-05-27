/* Copyright 2025 R. Thomas
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
#include <LIEF/DWARF/editor/Variable.hpp>

#include "FunctionEngine.hpp"
#include "TypeEngine.hpp"

#include "log.hpp"

namespace bn = BinaryNinja;
namespace dw = LIEF::dwarf::editor;

namespace dwarf_plugin {

dw::Function* FunctionEngine::add_function(bn::Function& func) {
  bn::Ref<bn::Symbol> sym = func.GetSymbol();
  std::unique_ptr<dw::Function> dw_func = unit_.create_function(sym->GetShortName());
  BN_DEBUG("Adding function: {}", sym->GetShortName());
  std::vector<BNAddressRange> ranges = func.GetAddressRanges();
  if (ranges.size() == 1) {
    dw_func->set_low_high(ranges[0].start, ranges[0].end);
  } else {
    std::vector<dw::Function::range_t> dw_ranges;
    dw_ranges.reserve(ranges.size());
    for (const BNAddressRange& range : ranges) {
      dw::Function::range_t dw_range{range.start, range.end};
      dw_ranges.push_back(dw_range);
    }
    dw_func->set_ranges(dw_ranges);
  }

  if (ranges[0].start != func.GetStart()) {
    dw_func->set_address(func.GetStart());
  }

  auto ret_type = func.GetReturnType();
  if (!ret_type->IsVoid()) {
    dw_func->set_return_type(types_.add_type(ret_type->GetTypeName(), *ret_type));
  }

  std::vector<bn::FunctionParameter> parameters = func.GetType()->GetParameters();
  for (size_t i = 0; i < parameters.size(); ++i) {
    const bn::FunctionParameter& p = parameters[i];
    std::string name = p.name.empty() ? fmt::format("arg_{}", i) : p.name;
    dw::Type& type = types_.add_type(p.type->GetTypeName(), *p.type);
    dw_func->add_parameter(name, type);
  }

  for (const auto& [addr, stack_var] : func.GetStackLayout()) {
    for (const bn::VariableNameAndType& info : stack_var) {
      if (!info.autoDefined) {
        std::unique_ptr<dw::Variable> dw_var = dw_func->create_stack_variable(info.name);
        dw_var->set_stack_offset(std::abs(addr));
        if (bn::Ref<bn::Type> var_type = info.type) {
          dw::Type& dw_type = types_.add_type(var_type->GetTypeName(), *var_type);
          dw_var->set_type(dw_type);
        }
      }
    }
  }

  for (const bn::Ref<bn::BasicBlock>& BB : func.GetBasicBlocks()) {
    dw_func->add_lexical_block(BB->GetStart(), BB->GetEnd());
  }

  //for (uint64_t addr : func.GetCommentedAddresses()) {
  //  const std::string& comment = func.GetCommentForAddress(addr);
  //  if (!comment.empty()) {
  //    dw_func->add_label(addr, comment);
  //  }
  //}

  BNSymbolBinding binding = sym->GetBinding();
  const bool is_external = binding == GlobalBinding || binding == WeakBinding;
  if (is_external) {
    dw_func->set_external();
  }

  return functions_.insert(
    {func.GetStart(), std::move(dw_func)}
  ).first->second.get();
}
}
