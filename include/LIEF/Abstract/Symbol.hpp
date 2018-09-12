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
#ifndef LIEF_ABSTRACT_SYMBOLS_H_
#define LIEF_ABSTRACT_SYMBOLS_H_

#include <string>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
class LIEF_API Symbol : public Object {
  public:
  Symbol(void);
  Symbol(const std::string& name);
  Symbol(const std::string& name, uint64_t value);
  Symbol(const std::string& name, uint64_t value, uint64_t size);
  Symbol(const Symbol&);
  Symbol& operator=(const Symbol&);
  virtual ~Symbol(void);

  void swap(Symbol& other);

  //! @brief Return symbol name
  virtual const std::string& name(void) const;

  virtual std::string& name(void);

  //! @brief Set symbol name
  virtual void name(const std::string& name);

  // Symbol's value
  virtual uint64_t value(void) const;
  virtual void     value(uint64_t value);

  virtual uint64_t size(void) const;
  virtual void     size(uint64_t value);

  //! @brief Method so that the ``visitor`` can visit us
  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& entry);

  protected:
  std::string name_;
  uint64_t value_;
  uint64_t size_;
};
}

#endif

