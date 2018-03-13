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
#ifndef LIEF_MACHO_RELOCATION_OBJECT_COMMAND_H_
#define LIEF_MACHO_RELOCATION_OBJECT_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"

#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/Relocation.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;

class LIEF_API RelocationObject : public Relocation {

  friend class BinaryParser;

  public:
    using Relocation::Relocation;
    RelocationObject(void);
    RelocationObject(const relocation_info *relocinfo);
    RelocationObject(const scattered_relocation_info *scattered_relocinfo);

    RelocationObject& operator=(RelocationObject other);
    RelocationObject(const RelocationObject& other);

    void swap(RelocationObject& other);

    virtual ~RelocationObject(void);

    virtual RelocationObject* clone(void) const override;

    virtual bool is_pc_relative(void) const override;

    virtual size_t size(void) const override;

    virtual uint64_t address(void) const override;

    //! @brief ``true`` if the relocation is a scattered one
    bool is_scattered(void) const;

    //! @brief For **scattered** relocations,
    //! The address of the relocatable expression for the item in the file that needs
    //! to be updated if the address is changed.
    //!
    //! For relocatable expressions with the difference of two section addresses,
    //! the address from which to subtract (in mathematical terms, the minuend)
    //! is contained in the first relocation entry and the address to subtract (the subtrahend)
    //! is contained in the second relocation entry.
    int32_t value(void) const;

    //! @brief Origin of the relocation
    virtual RELOCATION_ORIGINS origin(void) const override;

    virtual void pc_relative(bool val) override;
    virtual void size(size_t size) override;

    void value(int32_t value);

    bool operator==(const RelocationObject& rhs) const;
    bool operator!=(const RelocationObject& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    bool               is_pcrel_;
    bool               is_scattered_;
    int32_t            value_;
};

}
}
#endif
