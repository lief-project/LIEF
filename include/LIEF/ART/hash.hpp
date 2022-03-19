/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_ART_HASH_H_
#define LIEF_ART_HASH_H_

#include "LIEF/ART.hpp"
#include "LIEF/hash.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ART {

class LIEF_API Hash : public LIEF::Hash {
 public:
  static size_t hash(const Object& obj);

 public:
  using LIEF::Hash::Hash;
  using LIEF::Hash::visit;

 public:
  void visit(const File& file) override;
  void visit(const Header& header) override;

  ~Hash() override;
};

}  // namespace ART
}  // namespace LIEF

#endif
