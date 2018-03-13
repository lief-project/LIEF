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
#ifndef LIEF_ABSTRACT_RELOCATION_H_
#define LIEF_ABSTRACT_RELOCATION_H_

#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
class LIEF_API Relocation : public Object {

  public:
    //! @brief Default CTOR
    Relocation(void);

    //! @brief CTOR from relocation's address and size
    Relocation(uint64_t address, uint8_t size);

    virtual ~Relocation(void);

    Relocation& operator=(const Relocation&);
    Relocation(const Relocation&);
    void swap(Relocation& other);

    //! @brief Relocation's Address
    virtual uint64_t address(void) const;

    //! @brief Relocation size in **bits**
    virtual size_t size(void) const;

    virtual void address(uint64_t address);
    virtual void size(size_t size);

    //! @brief Method so that the ``visitor`` can visit us
    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Relocation& rhs) const;
    bool operator!=(const Relocation& rhs) const;


    //! @brief Comparaison based on the Relocation's **address**
    bool operator<(const Relocation& rhs) const;

    //! @brief Comparaison based on the Relocation's **address**
    bool operator<=(const Relocation& rhs) const;

    //! @brief Comparaison based on the Relocation's **address**
    bool operator>(const Relocation& rhs) const;

    //! @brief Comparaison based on the Relocation's **address**
    bool operator>=(const Relocation& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& entry);

  protected:
    uint64_t address_;
    uint8_t  size_;
    // type_;

};


}
#endif
