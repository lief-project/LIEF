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
#ifndef LIEF_PE_EXPORT_H_
#define LIEF_PE_EXPORT_H_

#include <iostream>
#include <vector>
#include <string>
#include <functional>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/type_traits.hpp"
#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/ExportEntry.hpp"

namespace LIEF {
namespace PE {

class Builder;
class Parser;

class LIEF_API Export : public Object {

  friend class Builder;
  friend class Parser;


  public:
  Export(void);
  Export(const pe_export_directory_table *header);
  Export(const Export&);
  Export& operator=(const Export&);
  virtual ~Export(void);

  uint32_t                      export_flags(void) const;
  uint32_t                      timestamp(void) const;
  uint16_t                      major_version(void) const;
  uint16_t                      minor_version(void) const;
  uint32_t                      ordinal_base(void) const;
  const std::string&            name(void) const;
  it_export_entries             entries(void);
  it_const_export_entries       entries(void) const;

  void export_flags(uint32_t flags);
  void timestamp(uint32_t timestamp);
  void major_version(uint16_t major_version);
  void minor_version(uint16_t minor_version);
  void ordinal_base(uint32_t ordinal_base);
  void name(const std::string& name);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Export& rhs) const;
  bool operator!=(const Export& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Export& exp);

  private:
  uint32_t         exportFlags_;
  uint32_t         timestamp_;
  uint16_t         majorVersion_;
  uint16_t         minorVersion_;
  uint32_t         ordinalBase_;
  std::string      name_;
  export_entries_t entries_;

};

}
}

#endif /* PE_EXPORT_H_ */
