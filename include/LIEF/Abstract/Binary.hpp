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
#ifndef LIEF_ABSTRACT_BINARY_H_
#define LIEF_ABSTRACT_BINARY_H_

#include <vector>
#include <memory>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/errors.hpp"

#include "LIEF/Abstract/Header.hpp"
#include "LIEF/Abstract/Function.hpp"

//! LIEF namespace
namespace LIEF {
class Section;
class Relocation;
class Symbol;

//! Abstract binary that exposes an uniform API for the
//! different executable file formats
class LIEF_API Binary : public Object {

  public:

  //! Type of a virtual address
  enum class VA_TYPES {
    AUTO = 0, ///< Try to guess if it's relative or not
    RVA  = 1, ///< Relative
    VA   = 2, ///< Absolute
  };

  using functions_t = std::vector<Function>;

  //! Internal container
  using sections_t = std::vector<Section*>;

  //! Iterator that outputs LIEF::Section&
  using it_sections = ref_iterator<sections_t>;

  //! Iterator that outputs const LIEF::Section&
  using it_const_sections = const_ref_iterator<sections_t>;

  //! Internal container
  using symbols_t = std::vector<Symbol*>;

  //! Iterator that outputs LIEF::Symbol&
  using it_symbols = ref_iterator<symbols_t>;

  //! Iterator that outputs const LIEF::Symbol&
  using it_const_symbols = const_ref_iterator<symbols_t>;

  //! Internal container
  using relocations_t = std::vector<Relocation*>;

  //! Iterator that outputs LIEF::Relocation&
  using it_relocations = ref_iterator<relocations_t>;

  //! Iterator that outputs const LIEF::Relocation&
  using it_const_relocations = const_ref_iterator<relocations_t>;

  public:
  Binary();
  virtual ~Binary();

  Binary& operator=(const Binary&);
  Binary(const Binary&);

  //! Executable format (ELF, PE, Mach-O) of the underlying binary
  EXE_FORMATS format() const;

  //! Return the abstract header of the binary
  Header header() const;

  //! Return an iterator over the abstracted symbols in which the elements **can** be modified
  it_symbols symbols();

  //! Return an iterator over the abstracted symbols in which the elements **can't** be modified
  it_const_symbols  symbols() const;

  //! Check if a Symbol with the given name exists
  bool has_symbol(const std::string& name) const;

  //! Return the Symbol with the given name
  //! If the symbol does not exist, return a nullptr
  const Symbol* get_symbol(const std::string& name) const;

  Symbol* get_symbol(const std::string& name);

  //! Return an iterator over the binary's sections (LIEF::Section)
  it_sections sections();
  it_const_sections sections() const;

  //! Remove **all** the sections in the underlying binary
  virtual void remove_section(const std::string& name, bool clear = false) = 0;

  //! Return an iterator over the binary relocation (LIEF::Relocation)
  it_relocations       relocations();
  it_const_relocations relocations() const;

  //! Binary's entrypoint (if any)
  virtual uint64_t entrypoint() const = 0;

  //! Binary's name
  const std::string& name() const;

  //! Binary's original size
  uint64_t original_size() const;

  //! Return the functions exported by the binary
  functions_t exported_functions() const;

  //! Return libraries which are imported by the binary
  std::vector<std::string> imported_libraries() const;

  //! Return functions imported by the binary
  functions_t imported_functions() const;

  //! Return the address of the given function name
  virtual result<uint64_t> get_function_address(const std::string& func_name) const;

  //! Method so that a ``visitor`` can visit us
  void accept(Visitor& visitor) const override;

  std::vector<uint64_t> xref(uint64_t address) const;

  //! Patch the content at virtual address @p address with @p patch_value
  //!
  //! @param[in] address        Address to patch
  //! @param[in] patch_value    Patch to apply
  //! @param[in] addr_type      Specify if the address should be used as an
  //!                           absolute virtual address or a RVA
  virtual void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value,
                             VA_TYPES addr_type = VA_TYPES::AUTO) = 0;

  //! Patch the address with the given value
  //!
  //! @param[in] address      Address to patch
  //! @param[in] patch_value  Patch to apply
  //! @param[in] size         Size of the value in **bytes** (1, 2, ... 8)
  //! @param[in] addr_type    Specify if the address should be used as an absolute virtual address or an RVA
  virtual void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t),
                             VA_TYPES addr_type = VA_TYPES::AUTO) = 0;

  //! Return the content located at the given virtual address
  virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address,
                                        uint64_t size, VA_TYPES addr_type = VA_TYPES::AUTO) const = 0;

  //! Change the binary's name
  void name(const std::string& name);

  //! @brief Change binary's original size.
  //!
  //! @warning
  //! This function should be used carefully as some optimizations
  //! can be performed with this value
  void original_size(uint64_t size);

  //! Check if the binary is position independent
  virtual bool is_pie() const = 0;

  //! Check if the binary uses ``NX`` protection
  virtual bool has_nx() const = 0;

  //! Default image base address if the ASLR is not enabled.
  virtual uint64_t imagebase() const = 0;

  //! Constructor functions that are called prior any other functions
  virtual functions_t ctor_functions() const = 0;

  //! Convert the given offset into a virtual address.
  //!
  //! @param[in] offset   The offset to convert.
  //! @param[in] slide    If not 0, it will replace the default base address (if any)
  virtual result<uint64_t> offset_to_virtual_address(uint64_t offset, uint64_t slide = 0) const = 0;

  virtual std::ostream& print(std::ostream& os) const;

  //! Build & transform the Binary object representation into a *real* executable
  virtual void write(const std::string& name) = 0;
  virtual void write(std::ostream& os) = 0;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Binary& binary);

  protected:
  EXE_FORMATS format_ = EXE_FORMATS::FORMAT_UNKNOWN;
  std::string name_;

  uint64_t original_size_ = 0;

  // These functions need to be overloaded by the object that claims to extend this Abstract Binary
  virtual Header get_abstract_header() const = 0;
  virtual symbols_t get_abstract_symbols() = 0;
  virtual sections_t get_abstract_sections() = 0;
  virtual relocations_t get_abstract_relocations() = 0;

  virtual functions_t  get_abstract_exported_functions() const = 0;
  virtual functions_t  get_abstract_imported_functions() const = 0;
  virtual std::vector<std::string>  get_abstract_imported_libraries() const = 0;
};
}

#endif
