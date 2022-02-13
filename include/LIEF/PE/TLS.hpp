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
#ifndef LIEF_PE_TLS_H_
#define LIEF_PE_TLS_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"


namespace LIEF {
namespace PE {

class Parser;
class Builder;
class DataDirectory;
class Section;

namespace details {
struct pe32_tls;
struct pe64_tls;
}

//! Class which represents the PE Thread Local Storage
//!
//! This PE structure is also used to implement binary/library constructors.
class LIEF_API TLS : public Object {
  friend class Parser;
  friend class Builder;

  public:
  TLS();
  TLS(const details::pe32_tls& header);
  TLS(const details::pe64_tls& header);
  virtual ~TLS();

  TLS(const TLS& copy);
  TLS& operator=(TLS copy);
  void swap(TLS& other);

  //! List of the callback associated with the current TLS.
  //!
  //! These functions are called before any other functions of the PE binary.
  const std::vector<uint64_t>&  callbacks() const;


  //! Pair ``(start address, end address)`` of the TLS template.
  //! The template is a block of data that is used to initialize TLS data.
  //! The system copies all of this data each time a thread is created, so it must not be
  //! corrupted.

  //! @note
  //! These addresses are not RVA. It is addresses for which there should be a base
  //! relocation in the ``.reloc`` section.
  std::pair<uint64_t, uint64_t> addressof_raw_data() const;

  //! The location to receive the TLS index, which the loader assigns.
  //! This location is in an ordinary data section, so it can be given a symbolic name that is accessible
  //! to the program.
  uint64_t addressof_index() const;


  //! The pointer to an array of TLS callback functions.
  //!
  //! The array is null-terminated, so if no callback function
  //! is supported, this field points to 4 bytes set to zero.
  uint64_t addressof_callbacks() const;

  //! The size in bytes of the template, beyond the initialized data delimited by
  //! the addressof_raw_data field.
  //! The total template size should be the same as the total size of TLS data in the image file.
  //! The zero fill is the amount of data that comes after the initialized nonzero data.
  uint32_t sizeof_zero_fill() const;

  //! The four bits [23:20] describe alignment info.
  //! Possible values are those defined as IMAGE_SCN_ALIGN_*, which are also used to
  //! describe alignment of section in object files. The other 28 bits are reserved for future use.
  uint32_t characteristics() const;

  //! The data template content
  const std::vector<uint8_t>& data_template() const;

  //! True if there is a data directory associated with this entry
  bool has_data_directory() const;

  //! Return the DataDirectory associated with this object or a nullptr
  //! If it exists, its type should be DATA_DIRECTORY::TLS_TABLE
  DataDirectory*       directory();
  const DataDirectory* directory() const;

  //! Check if there is a section associated with this entry
  bool has_section() const;

  //! The section associated with the entry (or a nullptr)
  Section* section();
  const Section* section() const;

  void callbacks(const std::vector<uint64_t>& callbacks);
  void addressof_raw_data(std::pair<uint64_t, uint64_t> VAOfRawData);
  void addressof_index(uint64_t addressOfIndex);
  void addressof_callbacks(uint64_t addressOfCallbacks);
  void sizeof_zero_fill(uint32_t sizeOfZeroFill);
  void characteristics(uint32_t characteristics);
  void data_template(const std::vector<uint8_t>& dataTemplate);

  void accept(Visitor& visitor) const override;

  bool operator==(const TLS& rhs) const;
  bool operator!=(const TLS& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const TLS& entry);

  private:
  std::vector<uint64_t>         callbacks_;
  std::pair<uint64_t, uint64_t> VAOfRawData_;
  uint64_t                      addressof_index_ = 0;
  uint64_t                      addressof_callbacks_ = 0;
  uint32_t                      sizeof_zero_fill_ = 0;
  uint32_t                      characteristics_ = 0;
  DataDirectory*                directory_ = nullptr;
  Section*                      section_ = nullptr;
  std::vector<uint8_t>          data_template_;

};
}
}
#endif
