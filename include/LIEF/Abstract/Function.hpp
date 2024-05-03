/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_ABSTRACT_FUNCTION_H
#define LIEF_ABSTRACT_FUNCTION_H

#include <vector>
#include <string>
#include <set>

#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/visibility.h"

namespace LIEF {

//! Class that represents a function in the binary
class LIEF_API Function : public Symbol {
  public:
  //! Flags used to characterize the semantic
  //! of the function
  enum class FLAGS {
    NONE = 0,
    //! The function acts as constructor.
    //!
    //! Usually this flag is associated with functions
    //! that are located in the ``.init_array``, ``__mod_init_func`` or ``.tls`` sections
    CONSTRUCTOR,

    //! The function acts a destructor.
    //!
    //! Usually this flag is associated with functions
    //! that are located in the ``.fini_array`` or ``__mod_term_func`` sections
    DESTRUCTOR,

    //! The function is associated with Debug information
    DEBUG_INFO,

    //! The function is exported by the binary and the address() method
    //! returns its virtual address in the binary
    EXPORTED,

    //! The function is **imported** by the binary and the address() should return 0
    IMPORTED,
  };

  using flags_list_t = std::vector<FLAGS>;
  using flags_t      = std::set<FLAGS>;

  public:
  Function();
  Function(const std::string& name);
  Function(uint64_t address);
  Function(const std::string& name, uint64_t address);
  Function(const std::string& name, uint64_t address, const flags_list_t& flags);
  Function(const Function&);
  Function& operator=(const Function&);
  ~Function() override;

  //! List of FLAGS
  flags_list_t flags() const;

  //! Add a flag to the current function
  Function& add(FLAGS f);

  //! Address of the current function. For functions that are set with the FLAGS::IMPORTED flag,
  //! this value is likely 0.
  uint64_t address() const;
  void address(uint64_t address);

  //! Method so that the ``visitor`` can visit us
  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Function& entry);

  protected:
  flags_t flags_;
};
}

#endif

