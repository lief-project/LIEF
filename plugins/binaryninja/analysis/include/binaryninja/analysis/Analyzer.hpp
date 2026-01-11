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
#include <memory>
#include <cassert>

namespace BinaryNinja {
class BinaryView;
}

namespace analysis_plugin {
class TypeBuilder;
class Analyzer {
  public:
  Analyzer(BinaryNinja::BinaryView& bv, std::unique_ptr<TypeBuilder> ty_builder);

  static std::unique_ptr<Analyzer> from_bv(BinaryNinja::BinaryView& bv);

  virtual void run() = 0;

  BinaryNinja::BinaryView& bv() {
    assert(bv_ != nullptr);
    return *bv_;
  }

  TypeBuilder& tyb() {
    assert(type_builder_ != nullptr);
    return *type_builder_;
  }

  virtual ~Analyzer();

  protected:
  BinaryNinja::BinaryView* bv_ = nullptr;
  std::unique_ptr<TypeBuilder> type_builder_;
};
}
