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
#ifndef LIEF_PE_EXPORT_ENTRY_H_
#define LIEF_PE_EXPORT_ENTRY_H_

#include <string>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/Abstract/Symbol.hpp"

namespace LIEF {
namespace PE {

class Builder;
class Parser;

//! Class which represents a PE Export entry (cf. PE::Export)
class LIEF_API ExportEntry : public LIEF::Symbol {

  friend class Builder;
  friend class Parser;

  public:
  struct LIEF_API forward_information_t {
    std::string library;
    std::string function;

    operator bool() const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const forward_information_t& info);
  };

  public:
  ExportEntry();
  ExportEntry(uint32_t address, bool is_extern,
              uint16_t ordinal, uint32_t function_rva);
  ExportEntry(const ExportEntry&);
  ExportEntry& operator=(const ExportEntry&);
  virtual ~ExportEntry();

  uint16_t           ordinal() const;
  uint32_t           address() const;
  bool               is_extern() const;
  bool               is_forwarded() const;
  forward_information_t forward_information() const;

  uint32_t function_rva() const;

  void ordinal(uint16_t ordinal);
  void address(uint32_t address);
  void is_extern(bool is_extern);

  inline uint64_t value() const override {
    return address();
  }

  inline void value(uint64_t value) override {
    address(static_cast<uint32_t>(value));
  }

  inline void set_forward_info(std::string lib, std::string function)  {
    forward_info_.library =  std::move(lib);
    forward_info_.function = std::move(function);
  }

  void accept(Visitor& visitor) const override;

  bool operator==(const ExportEntry& rhs) const;
  bool operator!=(const ExportEntry& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ExportEntry& exportEntry);

  private:
  uint32_t function_rva_ = 0;
  uint16_t ordinal_ = 0;
  uint32_t address_ = 0;
  bool     is_extern_ = false;

  forward_information_t forward_info_;

};

}
}

#endif /* PE_EXPORTENTRY_H_ */
