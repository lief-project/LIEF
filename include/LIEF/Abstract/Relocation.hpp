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
#ifndef LIEF_ABSTRACT_RELOCATION_H_
#define LIEF_ABSTRACT_RELOCATION_H_

#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
//! Class which represents an abstracted Relocation
class LIEF_API Relocation : public Object {

  public:
  Relocation();

  //! Constructor from a relocation's address and size
  Relocation(uint64_t address, uint8_t size);

  virtual ~Relocation();

  Relocation& operator=(const Relocation&);
  Relocation(const Relocation&);
  void swap(Relocation& other);

  //! Relocation's address
  virtual uint64_t address() const;

  //! Relocation size in **bits**
  virtual size_t size() const;

  virtual void address(uint64_t address);
  virtual void size(size_t size);

  //! Method so that the ``visitor`` can visit us
  void accept(Visitor& visitor) const override;

  bool operator==(const Relocation& rhs) const;
  bool operator!=(const Relocation& rhs) const;

  //! Comparaison based on the Relocation's **address**
  virtual bool operator<(const Relocation& rhs) const;

  //! Comparaison based on the Relocation's **address**
  virtual bool operator<=(const Relocation& rhs) const;

  //! Comparaison based on the Relocation's **address**
  virtual bool operator>(const Relocation& rhs) const;

  //! Comparaison based on the Relocation's **address**
  virtual bool operator>=(const Relocation& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& entry);

  protected:
  uint64_t address_ = 0;
  uint8_t  size_ = 0;
};


}
#endif
