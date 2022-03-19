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
#include "LIEF/DEX/Prototype.hpp"

#include <numeric>

#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/hash.hpp"
#include "logging.hpp"

namespace LIEF {
namespace DEX {

Prototype::Prototype() = default;
Prototype::Prototype(const Prototype& other) = default;

const Type* Prototype::return_type() const { return return_type_; }

Type* Prototype::return_type() {
  return const_cast<Type*>(static_cast<const Prototype*>(this)->return_type());
}

Prototype::it_const_params Prototype::parameters_type() const {
  return params_;
}

Prototype::it_params Prototype::parameters_type() { return params_; }

void Prototype::accept(Visitor& visitor) const { visitor.visit(*this); }

bool Prototype::operator==(const Prototype& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Prototype::operator!=(const Prototype& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Prototype& type) {
  Prototype::it_const_params ps = type.parameters_type();
  if (const auto* t = type.return_type()) {
    os << *t;
  }
  os << " (";
  for (size_t i = 0; i < ps.size(); ++i) {
    if (i > 0) {
      os << ", ";
    }
    os << ps[i];
  }
  os << ")";

  return os;
}

Prototype::~Prototype() = default;

}  // namespace DEX
}  // namespace LIEF
