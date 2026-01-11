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

#include "binaryninja/dwarf-export/VarEngine.hpp"
#include "binaryninja/dwarf-export/TypeEngine.hpp"

#include "binaryninja/api_compat.hpp"

#include "log.hpp"

namespace bn = BinaryNinja;
namespace dw = LIEF::dwarf::editor;

namespace dwarf_plugin {

using namespace binaryninja;

dw::Variable* VarEngine::add_variable(const bn::DataVariable& var) {
  if (auto it = vars_.find(var.address); it != vars_.end()) {
    return it->second.get();
  }


  std::string name = fmt::format("data_{:04x}", var.address);
  bool is_external = false;
  if (bn::Ref<bn::Symbol> sym = bv_.GetSymbolByAddress(var.address)) {
    BNSymbolType type = sym->GetType();
    if (type == ExternalSymbol ||
        type == ImportedFunctionSymbol ||
        type == FunctionSymbol ||
        type == LibraryFunctionSymbol ||
        type == SymbolicFunctionSymbol
      )
    {
      return nullptr;
    }
    name = sym->GetFullName();
    BNSymbolBinding binding = sym->GetBinding();
    is_external = binding == GlobalBinding || binding == WeakBinding;
  }

  std::unique_ptr<dw::Variable> dw_var = unit_.create_variable(name);

  dw_var->set_addr(var.address);
  dw_var->set_type(types_.add_type(api_compat::get_type(var.type)));


  std::string comment = bv_.GetCommentForAddress(var.address);
  if (!comment.empty()) {
    dw_var->add_description(comment);
  }

  if (is_external) {
    dw_var->set_external();
  }

  return vars_.insert(
    {var.address, std::move(dw_var)}
  ).first->second.get();
}
}
