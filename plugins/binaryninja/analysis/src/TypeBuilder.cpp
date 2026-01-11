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
#include "binaryninja/analysis/TypeBuilder.hpp"
#include "log.hpp"

using namespace BinaryNinja;

namespace analysis_plugin {

Ref<Type> TypeBuilder::get_or_create(const std::string& name) {
  return nullptr;
}

Ref<Type> TypeBuilder::get(const std::string& name) {
  if (Ref<Type> type = bv_.GetTypeByName(QualifiedName(format_type(name)))) {
    return type;
  }

  if (auto it = cache_.find(format_type(name)); it != cache_.end()) {
    return it->second;
  }

  //if (Ref<Type> type = bv_.GetTypeByName(QualifiedName(name))) {
  //  BN_ERR("Found non-formatted name: {}", name);
  //  return type;
  //}

  if (auto it = cache_.find(name); it != cache_.end()) {
    return it->second;
  }

  return nullptr;
}

Ref<Type> TypeBuilder::create_struct(
    BinaryNinja::Structure& S, const std::string& name,
    std::optional<std::string> typedef_)
{
  Ref<Type> type = Type::StructureType(&S);
  QualifiedName type_qn(name);
  const std::string ty_src = default_type_src();
  std::string type_tyid = Type::GenerateAutoTypeId(ty_src, type_qn);
  bv_.DefineType(type_tyid, type_qn, type);
  if (typedef_) {
    const std::string& alt_name = *typedef_;
    QualifiedName typedef_qn(alt_name);
    std::string typedef_tyid = Type::GenerateAutoTypeId(ty_src, typedef_qn);

    NamedTypeReferenceBuilder ref_builder;
    ref_builder.SetTypeId(type_tyid);
    ref_builder.SetName(type_qn);

    Ref<Type> typedef_ty = Type::NamedType(ref_builder.Finalize());
    QualifiedName type_name_alt = bv_.DefineType(
        typedef_tyid, typedef_qn, typedef_ty);

    return typedef_ty;
  }

  return type;
}


Ref<Type> TypeBuilder::create_typedef(const std::string& name, const std::string& target) {
  Ref<Type> target_ty = bv_.GetTypeByName(target);
  if (target_ty == nullptr) {
    BN_ERR("Can't find type named {}", target);
    return nullptr;
  }

  QualifiedName type_qn(name);
  std::string type_id = Type::GenerateAutoTypeId(default_type_src(), type_qn);

  if (auto type = bv_.GetTypeByName(type_qn)) {
    return type;
  }

  QualifiedName alias = bv_.DefineType(
      type_id, type_qn,
      BinaryNinja::TypeBuilder::NamedType(
        target, target_ty
      ).Finalize());

  assert(bv_.GetTypeByName(type_qn) != nullptr);
  return bv_.GetTypeByName(type_qn);
}

}
