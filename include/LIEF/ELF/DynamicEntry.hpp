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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_H_
#define LIEF_ELF_DYNAMIC_ENTRY_H_

#include <string>
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/Visitable.hpp"

#include "LIEF/ELF/Structures.hpp"

namespace LIEF {
namespace ELF {

class DLL_PUBLIC DynamicEntry : public Visitable {
  public:

    DynamicEntry(const Elf64_Dyn* header);
    DynamicEntry(const Elf32_Dyn* header);
    DynamicEntry(void);
    DynamicEntry(DYNAMIC_TAGS tag, uint64_t value);

    DynamicEntry& operator=(const DynamicEntry&);
    DynamicEntry(const DynamicEntry&);
    virtual ~DynamicEntry(void);

    DYNAMIC_TAGS tag(void) const;
    uint64_t value(void) const;

    void tag(DYNAMIC_TAGS tag);
    void value(uint64_t value);

    virtual const std::string& name(void) const;
    virtual void name(const std::string& name);

    virtual std::vector<uint64_t>& array(void);
    virtual void array(const std::vector<uint64_t>& array);

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const;

    bool operator==(const DynamicEntry& rhs) const;
    bool operator!=(const DynamicEntry& rhs) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const DynamicEntry& entry);

  protected:
    DYNAMIC_TAGS tag_;
    uint64_t     value_;
};
}
}
#endif
