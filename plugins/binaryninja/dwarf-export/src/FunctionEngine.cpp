/* Copyright 2025 - 2026 R. Thomas
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
#include <LIEF/DWARF/editor/Function.hpp>

#include "binaryninja/dwarf-export/FunctionEngine.hpp"
#include "binaryninja/dwarf-export/TypeEngine.hpp"
#include "binaryninja/dwarf-export/log.hpp"
#include "binaryninja/api_compat.hpp"

#include "log.hpp"

namespace bn = BinaryNinja;
namespace dw = LIEF::dwarf::editor;

template <> class fmt::formatter<bn::InstructionTextToken> {
public:
  constexpr auto parse (format_parse_context& ctx) { return ctx.begin(); }
  template <typename Context>
  constexpr auto format (const bn::InstructionTextToken& T, Context& ctx) const {
    // or: format_to(ctx.out(), "{}", T.text);
    return detail::write(ctx.out(), T.text.c_str());
  }
};

namespace dwarf_plugin {

using namespace binaryninja;

dw::Function* FunctionEngine::add_function(bn::Function& func) {
  bn::Ref<bn::Symbol> sym = func.GetSymbol();
  const std::string& func_name = sym->GetShortName();

  std::unique_ptr<dw::Function> dw_func = unit_.create_function(func_name);
  BN_DEBUG("Adding function: {}", func_name);

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

  if (std::string comment = func.GetComment(); !comment.empty()) {
    dw_func->add_description(comment);
  }

  auto ret_type = func.GetReturnType();
  dw_func->set_return_type(types_.add_type(api_compat::get_type(ret_type)));

  std::vector<bn::FunctionParameter> parameters = func.GetType()->GetParameters();
  for (size_t i = 0; i < parameters.size(); ++i) {
    const bn::FunctionParameter& p = parameters[i];
    std::string name = p.name.empty() ? fmt::format("arg_{}", i) : p.name;
    dw::Type& type = types_.add_type(api_compat::get_type(p.type));
    std::unique_ptr<dw::Function::Parameter> P = dw_func->add_parameter(name, type);
    if (!p.defaultLocation) {
      if (p.location.type == BNVariableSourceType::RegisterVariableSourceType) {
        int64_t reg = p.location.storage;
        if (bn::Ref<bn::Platform> platform = func.GetPlatform()) {
          std::string reg_name = platform->GetArchitecture()->GetRegisterName(reg);
          if (!reg_name.empty()) {
            P->assign_register(reg_name);
          }
        }
      }
    }
  }

  for (const auto& [addr, stack_var] : func.GetStackLayout()) {
    for (const bn::VariableNameAndType& info : stack_var) {
      if (info.autoDefined) {
        continue;
      }

      std::unique_ptr<dw::Variable> dw_var = dw_func->create_stack_variable(info.name);
      dw_var->set_stack_offset(std::abs(addr));
      if (auto var_type = info.type; api_compat::as_bool(var_type)) {
        dw::Type& dw_type = types_.add_type(api_compat::get_type(var_type));
        dw_var->set_type(dw_type);
      }
    }
  }
  std::vector<uint64_t> commented_addresses = func.GetCommentedAddresses();
  std::stable_sort(commented_addresses.begin(), commented_addresses.end());

  std::vector<bn::Ref<bn::BasicBlock>> blocks = func.GetBasicBlocks();

  if (blocks.size() > 1) {
    for (bn::Ref<bn::BasicBlock> BB : blocks) {
      std::unique_ptr<dw::Function::LexicalBlock> LB =
        dw_func->add_lexical_block(BB->GetStart(), BB->GetEnd());
      if (LB == nullptr) {
        BN_WARN("Failed to add lexical block {}:[0x{:010x}, 0x{:010x}]", func_name,
                BB->GetStart(), BB->GetEnd());
        continue;
      }
      std::string comment = func.GetCommentForAddress(BB->GetStart());
      if (!comment.empty()) {
        LB->add_description(comment);
      }

      auto it = std::lower_bound(commented_addresses.begin(), commented_addresses.end(),
        BB->GetStart() + 1
      );

      if (it != commented_addresses.end()) {
        for (; it != commented_addresses.end() && *it < BB->GetEnd(); ++it) {
          const uint64_t addr = *it;
          size_t inst_size = bv_.GetInstructionLength(func.GetArchitecture(), addr);
          const std::string& comment = func.GetCommentForAddress(addr);
          assert(inst_size > 0);
          assert(!comment.empty());
          BN_DEBUG("Adding comment for: {:#x}: {}", addr, comment);

          std::unique_ptr<dw::Function::LexicalBlock> inst_block =
            LB->add_block(addr, addr + inst_size);
          if (inst_block == nullptr) {
            BN_WARN("Failed to create inst block for addr: {}:{:#x}", func_name,
                    addr);
            continue;
          }

          inst_block->add_description(comment);
        }
      }
    }
  } else if (blocks.size() == 1) {
    bn::Ref<bn::BasicBlock> main_block = blocks[0];
    std::string comment = func.GetCommentForAddress(main_block->GetStart());
    if (!comment.empty()) {
      dw_func->add_description(comment);
    }

    auto it = std::lower_bound(commented_addresses.begin(), commented_addresses.end(),
      main_block->GetStart() + 1
    );

    if (it != commented_addresses.end()) {
      for (; it != commented_addresses.end() && *it < main_block->GetEnd(); ++it) {
        const uint64_t addr = *it;
        const std::string& comment = func.GetCommentForAddress(addr);
        size_t inst_size = bv_.GetInstructionLength(func.GetArchitecture(), addr);

        assert(inst_size > 0);
        assert(!comment.empty());

        BN_DEBUG("Adding comment for: {:#x}: {}", addr, comment);

        std::unique_ptr<dw::Function::LexicalBlock> inst_block =
          dw_func->add_lexical_block(addr, addr + inst_size);
        if (inst_block == nullptr) {
          BN_WARN("Failed to create inst block for addr: {}:{:#x}", func_name,
                  addr);
          continue;
        }

        inst_block->add_description(comment);
      }
    }
  }

  BNSymbolBinding binding = sym->GetBinding();
  const bool is_external = binding == GlobalBinding || binding == WeakBinding;
  if (is_external) {
    dw_func->set_external();
  }

  return functions_.insert(
    {func.GetStart(), std::move(dw_func)}
  ).first->second.get();
}

std::string FunctionEngine::get_hlil_for_addr(BinaryNinja::Function& F, uint64_t addr) {
  std::string out;
  bn::Ref<bn::HighLevelILFunction> HLIL = F.GetHighLevelIL();
  if (HLIL == nullptr) {
    return out;
  }
  HLIL->VisitAllExprs([&] (const bn::HighLevelILInstruction& I) {
      for (const bn::DisassemblyTextLine& T : HLIL->GetExprText(I)) {
        if (T.addr != addr) {
          continue;
        }
        out = fmt::format("{:#x} {}", T.addr, fmt::join(T.tokens, ""));
        return true;
      }

      return false;
    }
  );
  return out;
}

}
