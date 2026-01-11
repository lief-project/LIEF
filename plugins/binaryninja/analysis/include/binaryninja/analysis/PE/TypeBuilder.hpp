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
#pragma once

#include "binaryninja/analysis/TypeBuilder.hpp"

namespace analysis_plugin::pe {

class TypeBuilder : public analysis_plugin::TypeBuilder {
  public:
  using analysis_plugin::TypeBuilder::TypeBuilder;

  std::string default_type_src() const override {
    return "lief-pe";
  }

  BinaryNinja::Ref<BinaryNinja::Type> get_or_create(const std::string& name) override;

  // Currently BinaryNinja is not aware of RVA (i.e. creating the associated
  // xref/symbols) as Ghidra does but in the future this could change so let
  // make an abstraction for that.
  BinaryNinja::Ref<BinaryNinja::Type> RVA() {
    using namespace BinaryNinja;
    QualifiedName name("RVA");

    if (auto type = bv_.GetTypeByName(name)) {
      return type;
    }

    bv_.DefineType(
        BinaryNinja::Type::GenerateAutoTypeId(default_type_src(), name),
          name, Type::IntegerType(/*width=*/4, /*sign=*/false, "RVA"));

    return bv_.GetTypeByName(name);
  }

  ~TypeBuilder() override = default;
};
}
