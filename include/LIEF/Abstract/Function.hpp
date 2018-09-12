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
#ifndef LIEF_ABSTRACT_FUNCTION_H_
#define LIEF_ABSTRACT_FUNCTION_H_

#include <string>
#include <set>

#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
class LIEF_API Function : public Symbol {
  public:
  enum class FLAGS {
    NONE        = 0,
    CONSTRUCTOR,
    DESTRUCTOR,
    DEBUG,
    EXPORTED,
    IMPORTED,
  };

  using flags_list_t = std::vector<FLAGS>;
  using flags_t      = std::set<FLAGS>;

  public:
  Function(void);
  Function(const std::string& name);
  Function(uint64_t adress);
  Function(const std::string& name, uint64_t address);
  Function(const std::string& name, uint64_t address, const flags_list_t& flags);
  Function(const Function&);
  Function& operator=(const Function&);
  virtual ~Function(void);

  flags_list_t flags(void) const;

  Function& add(FLAGS f);

  uint64_t address(void) const;
  void address(uint64_t address);

  //! @brief Method so that the ``visitor`` can visit us
  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Function& entry);

  protected:
  flags_t flags_;
};
}

#endif

