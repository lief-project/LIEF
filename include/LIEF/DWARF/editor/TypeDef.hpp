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
#ifndef LIEF_DWARF_EDITOR_TYPEDEF_TYPE_H
#define LIEF_DWARF_EDITOR_TYPEDEF_TYPE_H

#include "LIEF/DWARF/editor/Type.hpp"
#include "LIEF/visibility.h"


namespace LIEF::dwarf::editor {

/// This class represents a typedef (`DW_TAG_typedef`).
class LIEF_API TypeDef : public Type {
  public:
  template<typename... Args,
           typename = std::enable_if_t<std::is_constructible_v<Type, Args&&...>>>
  TypeDef(Args&&... args) :
    Type(std::forward<Args>(args)...) {}

  static bool classof(const Type* type);

  ~TypeDef() override = default;
};

}


#endif
