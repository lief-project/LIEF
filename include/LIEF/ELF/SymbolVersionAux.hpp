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
#ifndef LIEF_ELF_SYMBOL_VERSION_AUX_H_
#define LIEF_ELF_SYMBOL_VERSION_AUX_H_

#include <string>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {
class Parser;

//! @brief Class which modelize an Auxiliary Symbol version
class LIEF_API SymbolVersionAux : public Object {
  friend class Parser;
  public:
    SymbolVersionAux(const std::string& name);
    SymbolVersionAux(void);
    virtual ~SymbolVersionAux(void);

    SymbolVersionAux& operator=(const SymbolVersionAux&);
    SymbolVersionAux(const SymbolVersionAux&);

    //! @brief Smybol's aux name (e.g. ``GLIBC_2.2.5``)
    const std::string& name(void) const;

    void name(const std::string& name);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const SymbolVersionAux& rhs) const;
    bool operator!=(const SymbolVersionAux& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const SymbolVersionAux& symAux);

  protected:
    std::string name_;
};
}
}
#endif
