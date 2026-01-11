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
#include "binaryninja/analysis/AnalyzerBase.hpp"
#include "log.hpp"

#include "binaryninja/lief_utils.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

using namespace BinaryNinja;

namespace analysis_plugin {

void AnalyzerBase::define_type_at(
    uint64_t address, BinaryNinja::Ref<BinaryNinja::Type> type,
    std::optional<std::string> name, bool force)
{
  if (force) {
    bv_.UndefineDataVariable(address, /*blacklist=*/false);
  }

  if (auto var = get_defined_var(address)) {
    BN_DEBUG("Type '{}' already defined at 0x{:016x}",
        binaryninja::to_string(var->type->GetTypeName()), address);
    return;
  }

  if (name) {
    Ref<Symbol> bn_sym = new Symbol(DataSymbol, *name, address, NoBinding);
    bv_.DefineAutoSymbolAndVariableOrFunction(
        bv_.GetDefaultPlatform(), bn_sym, type);
  } else {
    bv_.DefineDataVariable(address, type);
  }
}


void AnalyzerBase::define_type_at(
    uint64_t address, BinaryNinja::Ref<BinaryNinja::Type> type,
    force_callback_t force, std::optional<std::string> name)
{
  if (auto var = get_defined_var(address)) {
    if (!force(*var)) {
      return;
    }
    bv_.UndefineDataVariable(address, /*blacklist=*/false);
  }

  if (name) {
    Ref<Symbol> bn_sym = new Symbol(DataSymbol, *name, address, NoBinding);
    bv_.DefineAutoSymbolAndVariableOrFunction(
        bv_.GetDefaultPlatform(), bn_sym, type);
  } else {
    bv_.DefineDataVariable(address, type);
  }

}

void AnalyzerBase::define_struct_at(uint64_t address, Ref<Type> type,
                                    std::optional<std::string> name, bool force)
{
  if (force) {
    bv_.UndefineDataVariable(address, /*blacklist=*/false);
  }

  if (auto var = get_defined_var(address)) {
    BN_DEBUG("Type '{}' already defined at 0x{:016x}",
        binaryninja::to_string(var->type->GetTypeName()), address);
    return;
  }

  if (name) {
    auto bn_sym = new Symbol(DataSymbol, *name, address, NoBinding);
    bv_.DefineAutoSymbolAndVariableOrFunction(
        bv_.GetDefaultPlatform(), bn_sym, type);
  } else {
    bv_.DefineDataVariable(address, type);
  }
}


std::optional<DataVariable> AnalyzerBase::get_defined_var(uint64_t addr) {
  DataVariable var;
  if (bv_.GetDataVariableAtAddress(addr, var) && !var.type->IsVoid()) {
    return var;
  }
  return std::nullopt;
}

void AnalyzerBase::define_array_at(
    uint64_t addr, BinaryNinja::Ref<BinaryNinja::Type> type,
    size_t count, std::optional<std::string> name, bool force)
{
  if (count == 0) {
    return;
  }

  if (force) {
    bv_.UndefineDataVariable(addr, /*blacklist=*/false);
  }

  if (auto var = get_defined_var(addr)) {
    BN_DEBUG("Type '{}' already defined at 0x{:016x}",
        binaryninja::to_string(var->type->GetTypeName()), addr);
    return;
  }

  auto array_ty = Type::ArrayType(type, count);
  if (name) {
    auto bn_sym = new Symbol(DataSymbol, *name, addr, NoBinding);
    bv_.DefineAutoSymbolAndVariableOrFunction(
        bv_.GetDefaultPlatform(), bn_sym, array_ty);
  } else {
    bv_.DefineDataVariable(addr, array_ty);
  }
}

void AnalyzerBase::define_blob(uint64_t addr, size_t size,
    std::optional<std::string> name, bool force)
{
  auto u8 = Type::IntegerType(/*width=*/1, /*sign=*/false, "uint8_t");
  return define_array_at(addr, u8, size, name, force);
}

void AnalyzerBase::define_struct_at(uint64_t address, const std::string& type,
                                    std::optional<std::string> name, bool force)
{
  Ref<Type> bn_type = bv_.GetTypeByName(QualifiedName(type));
  if (!bn_type) {
    BN_ERR("Type '{}' not found", type);
    return;
  }
  return define_struct_at(address, bn_type, name, force);
}

}
