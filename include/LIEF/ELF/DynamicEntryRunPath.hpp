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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_RUNPATH_H_
#define LIEF_ELF_DYNAMIC_ENTRY_RUNPATH_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {
class DLL_PUBLIC DynamicEntryRunPath : public DynamicEntry {

  public:
    DynamicEntryRunPath(const Elf64_Dyn* header);
    DynamicEntryRunPath(const Elf32_Dyn* header);
    DynamicEntryRunPath(void);

    DynamicEntryRunPath(const std::string& name = "");

    DynamicEntryRunPath& operator=(const DynamicEntryRunPath& copy);
    DynamicEntryRunPath(const DynamicEntryRunPath& copy);

    virtual const std::string& name(void) const override;
    virtual void name(const std::string& name) override;

    const std::string& runpath(void) const;
    void runpath(const std::string& runpath);

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    std::string runpath_;
};
}
}
#endif
