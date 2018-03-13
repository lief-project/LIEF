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
#ifndef LIEF_ELF_DYNAMIC_SHARED_OBJECT_H_
#define LIEF_ELF_DYNAMIC_SHARED_OBJECT_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {
class LIEF_API DynamicSharedObject : public DynamicEntry {

  public:
    using DynamicEntry::DynamicEntry;
    DynamicSharedObject(void);
    DynamicSharedObject(const std::string& name);

    DynamicSharedObject& operator=(const DynamicSharedObject&);
    DynamicSharedObject(const DynamicSharedObject&);

    const std::string& name(void) const;
    void name(const std::string& name);

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    std::string name_;
};
}
}
#endif
