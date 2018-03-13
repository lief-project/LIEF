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
#ifndef LIEF_PE_EXPORT_ENTRY_H_
#define LIEF_PE_EXPORT_ENTRY_H_

#include <string>
#include <memory>
#include <iostream>
#include <vector>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"


namespace LIEF {
namespace PE {

class Builder;
class Parser;

class LIEF_API ExportEntry : public Object {

  friend class Builder;
  friend class Parser;

  public:
  ExportEntry(void);
  ExportEntry(const ExportEntry&);
  ExportEntry& operator=(const ExportEntry&);
  virtual ~ExportEntry(void);

  const std::string& name(void) const;
  uint16_t           ordinal(void) const;
  uint32_t           address(void) const;
  bool               is_extern(void) const;

  void name(const std::string& name);
  void ordinal(uint16_t ordinal);
  void address(uint32_t address);
  void is_extern(bool is_extern);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ExportEntry& rhs) const;
  bool operator!=(const ExportEntry& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ExportEntry& exportEntry);

  private:
  std::string name_;
  uint16_t    ordinal_;
  uint32_t    address_;
  bool        is_extern_;

};

}
}

#endif /* PE_EXPORTENTRY_H_ */
