/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_PE_POGO_H_
#define LIEF_PE_POGO_H_
#include <array>
#include <set>
#include <vector>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/type_traits.hpp"
#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/PogoEntry.hpp"


namespace LIEF {
namespace PE {

class Builder;
class Parser;

class LIEF_API Pogo : public Object {

  friend class Builder;
  friend class Parser;

  public:
  Pogo(void);
  Pogo(POGO_SIGNATURES signature, const std::vector<PogoEntry>& entries);

  Pogo(const Pogo&);
  Pogo& operator=(const Pogo&);

  virtual Pogo* clone(void) const;

  POGO_SIGNATURES       signature() const;
  it_pogo_entries       entries(void);
  it_const_pogo_entries entries(void) const;

  void signature(POGO_SIGNATURES signature);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Pogo& rhs) const;
  bool operator!=(const Pogo& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Pogo& entry);

  virtual ~Pogo(void);

  protected:
  POGO_SIGNATURES signature_;
  pogo_entries_t entries_;
};

} // Namespace PE
} // Namespace LIEF

#endif
