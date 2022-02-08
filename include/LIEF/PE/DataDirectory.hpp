/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Builder;
class Parser;
class Binary;
class Section;

namespace details {
struct pe_data_directory;
}

//! Class that represents a PE data directory entry
class LIEF_API DataDirectory : public Object {

  friend class Builder;
  friend class Parser;
  friend class Binary;

  public:
  DataDirectory();
  DataDirectory(DATA_DIRECTORY type);
  DataDirectory(const details::pe_data_directory& header, DATA_DIRECTORY type);

  DataDirectory(const DataDirectory& other);
  DataDirectory& operator=(DataDirectory other);
  void swap(DataDirectory& other);
  virtual ~DataDirectory();

  //! The relative virtual address of the content of this data
  //! directory
  uint32_t RVA() const;

  //! The size of the content
  uint32_t size() const;

  //! Check if the content of this data directory is associated
  //! with a PE Cection
  bool has_section() const;

  //! Section associated with the DataDirectory
  Section* section();
  const Section* section() const;

  //! Type of the data directory
  DATA_DIRECTORY type() const;

  void size(uint32_t size);
  void RVA(uint32_t rva);

  void accept(Visitor& visitor) const override;

  bool operator==(const DataDirectory& rhs) const;
  bool operator!=(const DataDirectory& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const DataDirectory& entry);

  private:
  uint32_t       rva_ = 0;
  uint32_t       size_ = 0;
  DATA_DIRECTORY type_ = DATA_DIRECTORY::NUM_DATA_DIRECTORIES;
  Section*       section_ = nullptr;
};
}
}

#endif /* LIEF_PE_DATADIRECTORY_H_ */
