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
#ifndef LIEF_ABSTRACT_SYMBOLS_H_
#define LIEF_ABSTRACT_SYMBOLS_H_

#include <string>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {

//! This class represents a symbol in an executable format.
class LIEF_API Symbol : public Object {
  public:
  Symbol();
  Symbol(std::string name);
  Symbol(std::string name, uint64_t value);
  Symbol(std::string name, uint64_t value, uint64_t size);
  Symbol(const Symbol&);
  Symbol& operator=(const Symbol&);
  virtual ~Symbol();

  void swap(Symbol& other);

  //! Return the symbol's name
  virtual const std::string& name() const;
  virtual std::string& name();

  //! Set symbol name
  virtual void name(const std::string& name);

  // Symbol's value which is usually the **address** of the symbol
  virtual uint64_t value() const;
  virtual void     value(uint64_t value);

  //! This size of the symbol (when applicable)
  virtual uint64_t size() const;
  virtual void     size(uint64_t value);

  //! Method so that the ``visitor`` can visit us
  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& entry);

  protected:
  std::string name_;
  uint64_t value_ = 0;
  uint64_t size_ = 0;
};
}

#endif

