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
#ifndef LIEF_DWARF_TYPE_DYNAMIC_H
#define LIEF_DWARF_TYPE_DYNAMIC_H

#include "LIEF/DWARF/Type.hpp"
#include "LIEF/visibility.h"


namespace LIEF::dwarf::types {

/// This class represents a `DW_TAG_dynamic_type`
class LIEF_API Dynamic : public Type {
  public:
  template<typename... Args,
           typename = std::enable_if_t<std::is_constructible_v<Type, Args&&...>>>
  Dynamic(Args&&... args) :
    Type(std::forward<Args>(args)...) {}

  Dynamic(const Dynamic&) = delete;
  Dynamic& operator=(const Dynamic&) = delete;

  Dynamic(Dynamic&&) noexcept = default;
  Dynamic& operator=(Dynamic&&) noexcept = default;

  static bool classof(const Type* type) {
    return type->kind() == Type::KIND::DYNAMIC;
  }

  ~Dynamic() override;
};

}


#endif
