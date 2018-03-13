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
#ifndef LIEF_MACHO_EXPORT_INFO_COMMAND_H_
#define LIEF_MACHO_EXPORT_INFO_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"


namespace LIEF {
namespace MachO {

class BinaryParser;

class LIEF_API ExportInfo : public Object {

  friend class BinaryParser;

  public:
    ExportInfo(void);
    ExportInfo(uint64_t address, uint64_t flags, uint64_t offset = 0);

    ExportInfo& operator=(ExportInfo copy);
    ExportInfo(const ExportInfo& copy);
    void swap(ExportInfo& other);

    uint64_t node_offset(void) const;

    uint64_t flags(void) const;
    void flags(uint64_t flags);

    uint64_t address(void) const;
    void address(uint64_t addr);

    bool has_symbol(void) const;

    const Symbol& symbol(void) const;
    Symbol& symbol(void);

    virtual ~ExportInfo(void);

    bool operator==(const ExportInfo& rhs) const;
    bool operator!=(const ExportInfo& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const ExportInfo& export_info);

  private:
    uint64_t node_offset_;
    uint64_t flags_;
    uint64_t address_;
    Symbol* symbol_;


};

}
}
#endif
