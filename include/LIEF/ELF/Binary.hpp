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
#ifndef LIEF_ELF_BINARY_H_
#define LIEF_ELF_BINARY_H_

#include <vector>
#include <memory>

#include "LIEF/visibility.h"

#include "LIEF/iterators.hpp"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/DataHandler/Handler.hpp"
#include "LIEF/ELF/GnuHash.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/SysvHash.hpp"


namespace LIEF {
namespace ELF {
class Parser;
class Builder;

//! @brief Class which represent an ELF binary
class DLL_PUBLIC Binary : public LIEF::Binary {
  friend class Parser;
  friend class Builder;

  public:
    Binary(const std::string& name, ELF_CLASS type);

    Binary& operator=(const Binary& copy) = delete;
    Binary(const Binary& copy)            = delete;

    //! @brief Check if the given symbol is exported
    static bool is_exported(const Symbol& symbol);

    //! @brief Check if the given symbol is imported
    static bool is_imported(const Symbol& symbol);

    //! @brief Return binary's class (ELF32 or ELF64)
    ELF_CLASS type(void) const;

    //! @brief Return @link ELF::Header Elf header @endlink
    Header&       get_header(void);
    const Header& get_header(void) const;

    //! @brief Return binary's sections
    //!
    //! @warning
    //! This method return a vector of references thus you can
    //! modify vector's elements (section) but not add elements.
    it_sections                            get_sections(void);
    it_const_sections                      get_sections(void) const;

    //! @brief Return binary entrypoint
    virtual uint64_t                       entrypoint(void) const override;

    //! @brief Return binary's segments
    it_segments                            get_segments(void);
    it_const_segments                      get_segments(void) const;

    //! @brief Return binary's dynamic entries
    it_dynamic_entries                     get_dynamic_entries(void);
    it_const_dynamic_entries               get_dynamic_entries(void) const;

    //! @brief Return binary's dynamic symbols
    it_symbols                             get_dynamic_symbols(void);
    it_const_symbols                       get_dynamic_symbols(void) const;

    //! @brief Return symbols which are exported by the binary
    it_exported_symbols                    get_exported_symbols(void);
    it_const_exported_symbols              get_exported_symbols(void) const;

    //! @brief Return symbols which are imported by the binary
    it_imported_symbols                    get_imported_symbols(void);
    it_const_imported_symbols              get_imported_symbols(void) const;

    //! @brief Return statics symbols
    it_symbols                             get_static_symbols(void);
    it_const_symbols                       get_static_symbols(void) const;

    //! @brief Return symbol versions
    it_symbols_version                     get_symbols_version(void);
    it_const_symbols_version               get_symbols_version(void) const;

    //! @brief Return symbols version definition
    it_symbols_version_definition          get_symbols_version_definition(void);
    it_const_symbols_version_definition    get_symbols_version_definition(void) const;

    //! @brief Return Symbol version requirement
    it_symbols_version_requirement         get_symbols_version_requirement(void);
    it_const_symbols_version_requirement   get_symbols_version_requirement(void) const;

    //! @brief Return dynamic relocations
    it_relocations                         get_dynamic_relocations(void);
    it_const_relocations                   get_dynamic_relocations(void) const;

    //! @brief Return `plt.got` relocations
    it_relocations                         get_pltgot_relocations(void);
    it_const_relocations                   get_pltgot_relocations(void) const;

    //! @brief ``true`` if GNU hash is used
    //!
    //! @see get_gnu_hash and use_sysv_hash
    bool use_gnu_hash(void) const;

    //! @brief Return the GnuHash object in **readonly**
    const GnuHash& get_gnu_hash(void) const;

    //! @brief ``true`` if SYSV hash is used
    //!
    //! @see get_sysv_hash and use_gnu_hash
    bool use_sysv_hash(void) const;

    //! @brief Return the SysvHash object in **readonly**
    const SysvHash& get_sysv_hash(void) const;

    //! @brief Check if a section with the given name exists in the binary
    bool has_section(const std::string& name) const;

    //! @brief Return Section with the given `name`
    Section&       get_section(const std::string& name);
    const Section& get_section(const std::string& name) const;

    //! @brief Return `.text` section
    Section& get_text_section(void);

    //! @brief Return `.dynamic` section
    Section& get_dynamic_section(void);

    //! @brief Return hash section
    Section& get_hash_section(void);

    //! @brief Return section which holds static symbols
    Section& get_static_symbols_section(void);

    //! @brief Return program image base. For instance 0x40000
    //!
    //! To compute the image base, we look for the PT_PHDR segment header (phdr),
    //! and we return phdr->p_vaddr - phdr->p_offset
    uint64_t get_imagebase(void) const;

    //! @brief Return the size of the mapped binary
    uint64_t get_virtual_size(void) const;


    //! @brief Check if the binary uses a loader
    //! @see get_interpreter
    bool has_interpreter(void) const;

    //! @brief Return ELF interprer if any. (e.g. `/lib64/ld-linux-x86-64.so.2`)
    std::string get_interpreter(void) const;

    //! @brief Return static symbols and dynamic symbols
    it_symbols       get_symbols(void);
    it_const_symbols get_symbols(void) const;

    //! @brief Remove symbols with the given name in boths
    //!   * dynamic symbols
    //!   * static symbols
    //! @see remove_static_symbol, remove_dynamic_symbol
    void remove_symbol(const std::string& name);
    //void remove_symbol(Symbol* symbol);

    //!@brief Remove static symbols with the given name
    void remove_static_symbol(const std::string& name);
    void remove_static_symbol(Symbol* symbol);

    //!@brief Remove dynamic symbols with the given name
    void remove_dynamic_symbol(const std::string& name);

    //! @brief Remove the given symbol from the dynamic symbol table.
    //!
    //! As a side effect, it will remove any ELF::Relocation
    //! that refer to this symbol and the SymbolVersion (if any)
    //! associated with this symbol
    void remove_dynamic_symbol(Symbol* symbol);

    //! @brief Return the address of the given function name
    virtual uint64_t get_function_address(const std::string& func_name) const override;

    //! @brief Return the address of the given function name
    //! @param func_name The function's name target
    //! @param demangled Use the demangled name
    uint64_t get_function_address(const std::string& func_name, bool demangled) const;

    //! Add a new section in the binary
    //!
    //! @param[in] section The section object to insert
    //! @param[in] loaded  Boolean value to indicate that sections's data must be loaded
    //!
    //! @return The section added. The `size` and the `virtual address` may have changed.
    //!
    //! @warning
    //! This function will change the following attributes:
    //!
    //! - Header
    //!   + Header::section_headers_offset
    //!   + Header::numberof_sections
    //!   + Header::section_name_table_idx
    //!
    //! - Section
    //!   + Section::file_offset
    //!   + Section::virtual_address
    //!   + Section::virtual_size
    //!
    //! - Segments
    //!   + Segment::file_offset
    //!   + Segment::virtual_address
    //!   + Segment::virtual_size
    //!   + Segment::physical_size
    //!
    Section& add_section(const Section& section, bool loaded = true);

    //! @brief Add a static symbol
    Symbol& add_static_symbol(const Symbol& symbol);

    //! @brief Add a new segment in the binary
    //!
    //! The segment is inserted at the end
    //! @warning We assume that the binary is not position independent
    //!
    //! @return The segment added. `Virtual address` and `File Offset` may have changed
    Segment& add_segment(const Segment& segment, uint64_t base = 0x400000, bool force_note = false);

    //! @brief This function insert data in the binary
    //!
    //! @warning This function should be use for shared library
    //! whose the code is position independent (-fPIC).
    //! There could be some problem for PIE binary
    //!
    //! @param[in] content The data ton insert
    //! @return Return {offset, size} where offset is the content's offset
    //! in the binary and size the content's aligned.
    std::pair<uint64_t, uint64_t> insert_content(std::vector<uint8_t>& content);


    //! @brief Patch the content at virtual address @p address with @p patch_value
    //!
    //! @param[in] address Address to patch
    //! @param[in] patch_value Patch to apply
    virtual void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value) override;


    //! @brief Patch the address with the given value
    //!
    //! @param[in] address Address to patch
    //! @param[in] patch_value Patch to apply
    //! @param[in] size Size of the value in **bytes** (1, 2, ... 8)
    virtual void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t)) override;

    //! @brief Patch the imported symbol with the ``address``
    //!
    //! @param[in] symbol Imported symbol to patch
    //! @param[in] address New address
    void patch_pltgot(const Symbol& symbol, uint64_t address);


    //! @brief Patch the imported symbol's name with the ``address``
    //!
    //! @param[in] symbol_name Imported symbol's name to patch
    //! @param[in] address New address
    void patch_pltgot(const std::string& symbol_name, uint64_t address);


    //! @brief Strip the binary by removing static symbols
    void strip(void);

    //! @brief Remove a binary's section.
    //!
    //! We clear data used by this section and it's removed from
    //! section table
    void remove_section(const std::string& name);

    //! @brief Reconstruct the binary object and write it in `filename`
    //! @param filename Path to write the reconstructed binary
    void write(const std::string& filename);

    //! @brief Reconstruct the binary object and return his content as bytes
    std::vector<uint8_t> raw(void);

    //! @brief Convert a virtual address to an offset in the file
    uint64_t virtual_address_to_offset(uint64_t virtual_address) const;

    //! @brief Check if the binary has been compiled with `-fpie -pie` flags
    //!
    //! To do so we check if there is a `PT_INTERP` segment and if
    //! the binary type is `ET_DYN` (Shared object)
    bool is_pie(void) const;

    //! @brief Return the @link ELF::Section Section @endlink
    //! from the @p offset
    const Section& section_from_offset(uint64_t offset) const;
    Section&       section_from_offset(uint64_t offset);

    //! @brief Return the @link ELF::Section Section @endlink
    //! from the @p address
    const Section& section_from_virtual_address(uint64_t address) const;
    Section&       section_from_virtual_address(uint64_t address);

    //! @brief Return the @link ELF::Segment Segment @endlink
    //! from the @p address
    const Segment& segment_from_virtual_address(uint64_t address) const;
    Segment&       segment_from_virtual_address(uint64_t address);

    //! @brief Return the @link ELF::Segment Segment @endlink
    //! from the @p offset
    const Segment& segment_from_offset(uint64_t offset) const;
    Segment&       segment_from_offset(uint64_t offset);

    //! @brief Return the ELF::DynamicEntry associated with the given tag
    const DynamicEntry& dynamic_entry_from_tag(DYNAMIC_TAGS tag) const;
    DynamicEntry&       dynamic_entry_from_tag(DYNAMIC_TAGS tag);

    //! @brief Check if ELF::DynamicEntry associated with the given tag
    //! exists.
    bool has_dynamic_entry(DYNAMIC_TAGS tag) const;

    //! @brief Return the content located at virtual address
    virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const override;

    //! @brief Method so that the ``visitor`` can visit us
    virtual void accept(LIEF::Visitor& visitor) const override;

    //! @brief Apply the given permutation on the dynamic symbols table
    //!
    //! To avoid override by the ELF::Builder, one should set ELF::Builder::empties_gnuhash
    //! to ``true``
    void permute_dynamic_symbols(const std::vector<size_t>& permutation);


    //! @brief ``true`` if the binary embed notes
    bool has_notes(void) const;

    //! @brief Return the Note object if any
    //! @see has_note
    it_const_notes notes(void) const;

    it_notes notes(void);

    size_t hash(const std::string& name);

    virtual ~Binary(void);

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    Binary(void);

    //! @brief Return an abstraction of binary's section: LIEF::Section
    virtual LIEF::sections_t         get_abstract_sections(void) override;

    virtual LIEF::Header             get_abstract_header(void) const override;

    virtual std::vector<std::string> get_abstract_exported_functions(void) const override;
    virtual std::vector<std::string> get_abstract_imported_functions(void) const override;
    virtual std::vector<std::string> get_abstract_imported_libraries(void) const override;
    virtual LIEF::symbols_t          get_abstract_symbols(void) override;

    //! The binary type
    //! (i.e. `ELF32` or `ELF64`)
    ELF_CLASS         type_;

    //! The binary's header as an object
    Header                        header_;

    //! The binary's sections if any
    sections_t                    sections_;

    //! The binary's segments if any
    segments_t                    segments_;

    //! A list of the diffrents dynamic entries.
    dynamic_entries_t             dynamic_entries_;

    //! A list of dynamic symbols
    symbols_t                     dynamic_symbols_;

    //! A list of static symbols
    symbols_t                     static_symbols_;

    //! The binary's dynamic Relocations if any
    relocations_t                 dynamic_relocations_;

    //! .rela.plt
    relocations_t                 pltgot_relocations_;

    //! .gnu.version
    symbols_version_t             symbol_version_table_;

    //! gnu.version_r
    symbols_version_requirement_t symbol_version_requirements_;

    //! .gnu.version_d
    symbols_version_definition_t  symbol_version_definition_;

    //! .gnu.hash
    GnuHash                       gnu_hash_;

    //! .note
    notes_t                       notes_;

    //! .hash
    SysvHash                      sysv_hash_;

    //! object used to manage segments/sections
    DataHandler::Handler*         datahandler_;
};

}
}
#endif
