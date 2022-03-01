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
#ifndef LIEF_PE_DELAY_IMPORT_H
#define LIEF_PE_DELAY_IMPORT_H

#include <string>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/types.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"

#include "LIEF/PE/DelayImportEntry.hpp"

namespace LIEF {
namespace PE {

namespace details {
struct delay_imports;
}

//! Class that represents a PE delayed import.
class LIEF_API DelayImport : public Object {

  friend class Parser;
  friend class Builder;

  public:
  using entries_t        = std::vector<DelayImportEntry>;
  using it_entries       = ref_iterator<entries_t&>;
  using it_const_entries = const_ref_iterator<const entries_t&>;

  DelayImport();
  DelayImport(const details::delay_imports& import, PE_TYPE type);
  DelayImport(std::string name);

  ~DelayImport() override;

  DelayImport(const DelayImport&);
  DelayImport& operator=(const DelayImport&);

  DelayImport(DelayImport&&);
  DelayImport& operator=(DelayImport&&);

  void swap(DelayImport& other);

  //! According to the official PE specifications,
  //! this value is reserved and should be set to 0.
  uint32_t attribute() const;
  void attribute(uint32_t hdl);

  //! Return the library's name (e.g. `kernel32.dll`)
  const std::string& name() const;
  void name(std::string name);

  //! The RVA of the module handle (in the ``.data`` section)
  //! It is used for storage by the routine that is supplied to
  //! manage delay-loading.
  uint32_t handle() const;
  void handle(uint32_t hdl);

  //! RVA of the delay-load import address table.
  uint32_t iat() const;
  void iat(uint32_t iat);

  //! RVA of the delay-load import names table.
  //! The content of this table has the layout as the Import lookup table
  uint32_t names_table() const;
  void names_table(uint32_t value);

  //! RVA of the **bound** delay-load import address table or 0
  //! if the table does not exist.
  uint32_t biat() const;
  void biat(uint32_t value);

  //! RVA of the **unload** delay-load import address table or 0
  //! if the table does not exist.
  //!
  //! According to the PE specifications, this table is an
  //! exact copy of the delay import address table that can be
  //! used to to restore the original IAT the case of unloading.
  uint32_t uiat() const;
  void uiat(uint32_t value);

  //! The timestamp of the DLL to which this image has been bound.
  uint32_t timestamp() const;
  void timestamp(uint32_t value);

  //! Iterator over the DelayImport's entries (DelayImportEntry)
  it_entries entries();

  //! Iterator over the DelayImport's entries (DelayImportEntry)
  it_const_entries entries() const;

  void accept(Visitor& visitor) const override;

  bool operator==(const DelayImport& rhs) const;
  bool operator!=(const DelayImport& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const DelayImport& entry);

  private:
  uint32_t attribute_ = 0;
  std::string name_;
  uint32_t handle_ = 0;
  uint32_t iat_ = 0;
  uint32_t names_table_ = 0;
  uint32_t bound_iat_ = 0;
  uint32_t unload_iat_ = 0;
  uint32_t timestamp_ = 0;
  entries_t entries_;

  PE_TYPE type_ = PE_TYPE::PE32;
};

}
}

#endif
