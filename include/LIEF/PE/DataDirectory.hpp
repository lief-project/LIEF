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
#ifndef LIEF_PE_DATADIRECTORY_H_
#define LIEF_PE_DATADIRECTORY_H_

#include <memory>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/Section.hpp"


namespace LIEF {
namespace PE {

class Builder;
class Parser;
class Binary;

class LIEF_API DataDirectory : public Object {

  friend class Builder;
  friend class Parser;
  friend class Binary;

  public:
  DataDirectory(void);
  DataDirectory(DATA_DIRECTORY type);
  DataDirectory(const pe_data_directory *header, DATA_DIRECTORY type);

  DataDirectory(const DataDirectory& other);
  DataDirectory& operator=(DataDirectory other);
  void swap(DataDirectory& other);
  virtual ~DataDirectory(void);

  uint32_t       RVA(void) const;
  uint32_t       size(void) const;
  Section&       section(void);
  const Section& section(void) const;
  DATA_DIRECTORY type(void) const;
  bool           has_section(void) const;

  void size(uint32_t size);
  void RVA(uint32_t rva);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const DataDirectory& rhs) const;
  bool operator!=(const DataDirectory& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const DataDirectory& entry);

  private:
  uint32_t       rva_;
  uint32_t       size_;
  DATA_DIRECTORY type_;
  Section*       section_;
};
}
}

#endif /* LIEF_PE_DATADIRECTORY_H_ */
