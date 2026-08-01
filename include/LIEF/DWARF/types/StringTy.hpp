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
#ifndef LIEF_DWARF_STRING_TYPE_H
#define LIEF_DWARF_STRING_TYPE_H

#include "LIEF/DWARF/Type.hpp"
#include "LIEF/visibility.h"


namespace LIEF::dwarf::types {

/// This class represents a `DW_TAG_string_type`
class LIEF_API StringTy : public Type {
  public:
  template<typename... Args,
           typename = std::enable_if_t<std::is_constructible_v<Type, Args&&...>>>
  StringTy(Args&&... args) :
    Type(std::forward<Args>(args)...) {}

  StringTy(const StringTy&) = delete;
  StringTy& operator=(const StringTy&) = delete;

  StringTy(StringTy&&) noexcept = default;
  StringTy& operator=(StringTy&&) noexcept = default;

  static bool classof(const Type* type) {
    return type->kind() == Type::KIND::STRING;
  }

  ~StringTy() override;
};

}


#endif
