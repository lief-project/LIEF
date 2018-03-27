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
#ifndef LIEF_ABSTRACT_BINARY_H_
#define LIEF_ABSTRACT_BINARY_H_

#include <vector>
#include <memory>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/Abstract/type_traits.hpp"
#include "LIEF/Abstract/Header.hpp"
#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/Abstract/Relocation.hpp"

//! LIEF namespace
namespace LIEF {

//! @brief Abstract binary
class LIEF_API Binary : public Object {

  public:

    //! Type of a virtual address
    enum class VA_TYPES {
      AUTO = 0, ///< Guess if it's relative or not
      RVA  = 1, ///< Relative
      VA   = 2, ///< Absolute
    };

  public:
    Binary(void);
    virtual ~Binary(void);

    Binary& operator=(const Binary&);
    Binary(const Binary&);

    //! @brief Executable format (ELF, PE, Mach-O) of the underlying binary
    EXE_FORMATS format(void) const;

    //! @brief Return the abstract header of the binary
    Header header(void) const;

    //! @brief Return list of symbols whose elements **can** be modified
    it_symbols symbols(void);

    //! @brief Return list of symbols whose elements **can't** be modified
    it_const_symbols  symbols(void) const;

    //! @brief Check if a Symbol with the given name exists
    bool has_symbol(const std::string& name) const;

    //! @brief Return the Symbol with the given name
    const Symbol& get_symbol(const std::string& name) const;

    Symbol& get_symbol(const std::string& name);

    //! @brief Returns binary's sections
    it_sections       sections(void);
    it_const_sections sections(void) const;

    //! @brief Returns binary's relocations
    it_relocations       relocations(void);
    it_const_relocations relocations(void) const;

    //! @brief Binary's entrypoint (if any)
    virtual uint64_t entrypoint(void) const = 0;

    //! @brief Binary's name
    const std::string& name(void) const;

    //! @brief Binary's original size
    uint64_t original_size(void) const;

    //! @brief Return functions's name exported by the binary
    std::vector<std::string> exported_functions(void) const;

    //! @brief Return libraries which are imported by the binary
    std::vector<std::string> imported_libraries(void) const;

    //! @brief Return functions's name imported by the binary
    std::vector<std::string> imported_functions(void) const;

    //! @brief Return the address of the given function name
    virtual uint64_t get_function_address(const std::string& func_name) const;

    //! @brief Method so that a ``visitor`` can visit us
    virtual void accept(Visitor& visitor) const override;

    std::vector<uint64_t> xref(uint64_t address) const;

    //! @brief Patch the content at virtual address @p address with @p patch_value
    //!
    //! @param[in] address Address to patch
    //! @param[in] patch_value Patch to apply
    virtual void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, VA_TYPES addr_type = VA_TYPES::AUTO) = 0;

    //! @brief Patch the address with the given value
    //!
    //! @param[in] address Address to patch
    //! @param[in] patch_value Patch to apply
    //! @param[in] size Size of the value in **bytes** (1, 2, ... 8)
    virtual void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t), VA_TYPES addr_type = VA_TYPES::AUTO) = 0;

    //! @brief Return the content located at virtual address
    virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address, uint64_t size, VA_TYPES addr_type = VA_TYPES::AUTO) const = 0;

    //! @brief Change binary's name
    void name(const std::string& name);

    //! @brief Change binary's original size.
    //!
    //! @warning
    //! Should be used carefully because some optimizations can be
    //! done with this value
    void original_size(uint64_t size);

    //! @brief Check if the binary is position independent
    virtual bool is_pie(void) const = 0;

    //! @brief Check if the binary uses ``NX`` protection
    virtual bool has_nx(void) const = 0;

    virtual std::ostream& print(std::ostream& os) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Binary& binary);

  protected:
    std::string name_;

    uint64_t original_size_;

    virtual Header                    get_abstract_header(void) const = 0;
    virtual symbols_t                 get_abstract_symbols(void)      = 0;
    virtual sections_t                get_abstract_sections(void)     = 0;
    virtual relocations_t             get_abstract_relocations(void)  = 0;

    virtual std::vector<std::string>  get_abstract_exported_functions(void) const = 0;
    virtual std::vector<std::string>  get_abstract_imported_functions(void) const = 0;
    virtual std::vector<std::string>  get_abstract_imported_libraries(void) const = 0;


};
}

#endif
