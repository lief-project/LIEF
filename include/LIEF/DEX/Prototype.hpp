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
#ifndef LIEF_DEX_PROTOTYPE_H_
#define LIEF_DEX_PROTOTYPE_H_

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"
#include "LIEF/iterators.hpp"

namespace LIEF {
namespace DEX {
class Parser;
class Type;

//! Class which represents a DEX method prototype
class LIEF_API Prototype : public Object {
  friend class Parser;

  public:
  using parameters_type_t = std::vector<Type*>;
  using it_params         = ref_iterator<parameters_type_t>;
  using it_const_params   = const_ref_iterator<const parameters_type_t>;

  public:
  Prototype();
  Prototype(const Prototype& other);

  //! Type returned or a nullptr if not resolved
  const Type* return_type() const;
  Type* return_type();

  //! Types of the parameters
  it_const_params parameters_type() const;
  it_params parameters_type();

  void accept(Visitor& visitor) const override;

  bool operator==(const Prototype& rhs) const;
  bool operator!=(const Prototype& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Prototype& type);

  virtual ~Prototype();

  private:
  Type* return_type_ = nullptr;
  parameters_type_t params_;

};

} // Namespace DEX
} // Namespace LIEF
#endif
