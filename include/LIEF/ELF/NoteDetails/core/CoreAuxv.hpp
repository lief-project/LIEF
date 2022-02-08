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
#ifndef LIEF_ELF_CORE_AUXV_H_
#define LIEF_ELF_CORE_AUXV_H_

#include <vector>
#include <iostream>
#include <map>
#include <utility>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/ELF/enums.hpp"
#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;
class Note;

//! Class representing core Auxv object
class LIEF_API CoreAuxv : public NoteDetails {

  public:
  using NoteDetails::NoteDetails;

  using val_context_t = std::map<AUX_TYPE, uint64_t>;

  public:
  static CoreAuxv make(Note& note);

  CoreAuxv* clone() const override;

  //! Auxiliary values
  const val_context_t& values() const;

  //! Get an auxiliary value. If ``error`` is set,
  //! this function and the value exists, the function set the boolean value to ``false``
  //! Otherwise it set the value to ``true``
  uint64_t get(AUX_TYPE atype, bool* error = nullptr) const;

  //! Check if the given register is present in the info
  bool has(AUX_TYPE reg) const;

  void values(const val_context_t& ctx);

  bool set(AUX_TYPE atype, uint64_t value);

  bool operator==(const CoreAuxv& rhs) const;
  bool operator!=(const CoreAuxv& rhs) const;

  uint64_t& operator[](AUX_TYPE atype);

  void dump(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  virtual ~CoreAuxv();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CoreAuxv& note);

  protected:
  template <typename ELF_T>
  LIEF_LOCAL void parse_();

  template <typename ELF_T>
  LIEF_LOCAL void build_();

  void parse() override;
  void build() override;

  private:
  CoreAuxv(Note& note);

  val_context_t ctx_;
};


} // namepsace ELF
} // namespace LIEF

#endif
