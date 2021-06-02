/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include "LIEF/ELF/GnuHash.hpp"
#include "LIEF/ELF/SysvHash.hpp"


namespace LIEF {
namespace ELF {
namespace DataHandler {
class Handler;
}

class Section;
class Segment;
class DynamicEntry;
class Symbol;
class SymbolVersion;
class SymbolVersionRequirement;
class SymbolVersionDefinition;
class Note;
class Relocation;
class Parser;
class Builder;

//! Class which represent an ELF binary
class LIEF_API Binary : public LIEF::Binary {
  friend class Parser;
  friend class Builder;

  public:
  using string_list_t = std::vector<std::string>;
  using overlay_t     = std::vector<uint8_t>;

  public:
  Binary(const std::string& name, ELF_CLASS type);

  Binary& operator=(const Binary& ) = delete;
  Binary(const Binary& copy) = delete;

  //! Return binary's class (ELF32 or ELF64)
  ELF_CLASS type(void) const;

  //! Return @link ELF::Header Elf header @endlink
  Header&       header(void);
  const Header& header(void) const;

  //! Return the last offset used in binary
  //! according to section headers
  uint64_t last_offset_section(void) const;

  //! Return the last offset used in binary
  //! according to segment headers
  uint64_t last_offset_segment(void) const;

  //! Return the next virtual address available
  uint64_t next_virtual_address(void) const;

  //! Return binary's sections
  //!
  //! @warning
  //! This method return a vector of references thus you can
  //! modify vector's elements (section) but not add elements.
  it_sections       sections(void);
  it_const_sections sections(void) const;

  //! Return binary entrypoint
  virtual uint64_t entrypoint(void) const override;

  //! Return binary's segments
  it_segments       segments(void);
  it_const_segments segments(void) const;

  //! Return binary's dynamic entries
  it_dynamic_entries       dynamic_entries(void);
  it_const_dynamic_entries dynamic_entries(void) const;

  //! Add the given dynamic entry and return the entry added
  DynamicEntry& add(const DynamicEntry& entry);

  //! Add the given note and return the entry added
  Note& add(const Note& note);

  //! Remove the given dynamic entry
  void remove(const DynamicEntry& entry);

  //! Remove **all** dynamic entries with the given tag
  void remove(DYNAMIC_TAGS tag);

  //! Remove the given section
  void remove(const Section& section, bool clear = false);

  //! Remove the given note
  void remove(const Note& note);

  //! Remove **all** notes with the given type
  void remove(NOTE_TYPES tag);

  //! Return binary's dynamic symbols
  it_symbols       dynamic_symbols(void);
  it_const_symbols dynamic_symbols(void) const;

  //! Return symbols which are exported by the binary
  it_exported_symbols       exported_symbols(void);
  it_const_exported_symbols exported_symbols(void) const;

  //! Return symbols which are imported by the binary
  it_imported_symbols       imported_symbols(void);
  it_const_imported_symbols imported_symbols(void) const;

  //! Return statics symbols
  it_symbols       static_symbols(void);
  it_const_symbols static_symbols(void) const;

  //! Return symbol versions
  it_symbols_version       symbols_version(void);
  it_const_symbols_version symbols_version(void) const;

  //! Return symbols version definition
  it_symbols_version_definition       symbols_version_definition(void);
  it_const_symbols_version_definition symbols_version_definition(void) const;

  //! Return Symbol version requirement
  it_symbols_version_requirement       symbols_version_requirement(void);
  it_const_symbols_version_requirement symbols_version_requirement(void) const;

  //! Return dynamic relocations
  it_dynamic_relocations       dynamic_relocations(void);
  it_const_dynamic_relocations dynamic_relocations(void) const;

  Relocation& add_dynamic_relocation(const Relocation& relocation);
  Relocation& add_pltgot_relocation(const Relocation& relocation);

  //! Add relocation for object file (.o)
  //!
  //! The first parameter is the section to add while the second parameter
  //! is the LIEF::ELF::Section associated with the relocation.
  //!
  //! If there is an error, this function return a nullptr. Otherwise, it returns
  //! the relocation added.
  Relocation* add_object_relocation(const Relocation& relocation, const Section& section);

  //! Return `plt.got` relocations
  it_pltgot_relocations       pltgot_relocations(void);
  it_const_pltgot_relocations pltgot_relocations(void) const;

  //! Return relocations used in an object file (``*.o``)
  it_object_relocations       object_relocations(void);
  it_const_object_relocations object_relocations(void) const;

  //! Return **all** relocations present in the binary
  it_relocations       relocations(void);
  it_const_relocations relocations(void) const;

  //! Return relocation associated with the given address.
  //! ``nullptr`` if not found
  const Relocation* get_relocation(uint64_t address) const;
  Relocation*       get_relocation(uint64_t address);

  //! Return relocation associated with the given Symbol
  const Relocation* get_relocation(const Symbol& symbol) const;
  Relocation*       get_relocation(const Symbol& symbol);

  //! Return relocation associated with the given Symbol name
  const Relocation* get_relocation(const std::string& symbol_name) const;
  Relocation*       get_relocation(const std::string& symbol_name);

  //! ``true`` if GNU hash is used
  //!
  //! @see gnu_hash and use_sysv_hash
  bool use_gnu_hash(void) const;

  //! Return the GnuHash object in **readonly**
  const GnuHash& gnu_hash(void) const;

  //! ``true`` if SYSV hash is used
  //!
  //! @see sysv_hash and use_gnu_hash
  bool use_sysv_hash(void) const;

  //! Return the SysvHash object in **readonly**
  const SysvHash& sysv_hash(void) const;

  //! Check if a section with the given name exists in the binary
  bool has_section(const std::string& name) const;

  //! Check if a section that handle the given offset exists
  bool has_section_with_offset(uint64_t offset) const;

  //! Check if a section that handle the given virtual address exists
  bool has_section_with_va(uint64_t va) const;

  //! Return Section with the given `name`
  Section&       get_section(const std::string& name);
  const Section& get_section(const std::string& name) const;

  //! Return `.text` section
  Section& text_section(void);

  //! Return `.dynamic` section
  Section& dynamic_section(void);

  //! Return hash section
  Section& hash_section(void);

  //! Return section which holds static symbols
  Section& static_symbols_section(void);

  //! Return program image base. For instance 0x40000
  //!
  //! To compute the image base, we look for the PT_PHDR segment header (phdr),
  //! and we return phdr->p_vaddr - phdr->p_offset
  uint64_t imagebase(void) const override;

  //! Return the size of the mapped binary
  uint64_t virtual_size(void) const;

  //! Check if the binary uses a loader
  //! @see interpreter
  bool has_interpreter(void) const;

  //! Return ELF interprer if any. (e.g. `/lib64/ld-linux-x86-64.so.2`)
  const std::string& interpreter(void) const;

  //! Change the interpreter
  void interpreter(const std::string& interpreter);

  //! Return both static and dynamic symbols
  it_symbols       symbols(void);
  it_const_symbols symbols(void) const;

  //! Export the given symbol and create it if it doesn't exist
  Symbol& export_symbol(const Symbol& symbol);

  //! Export the symbol with the given name and create it if it doesn't exist
  Symbol& export_symbol(const std::string& symbol_name, uint64_t value = 0);

  //! Check if the symbol with the given ``name`` exists in the dynamic symbol table
  bool has_dynamic_symbol(const std::string& name) const;

  //! Get the dynamic symbol from the given name
  const Symbol& get_dynamic_symbol(const std::string& name) const;

  Symbol& get_dynamic_symbol(const std::string& name);

  //! Check if the symbol with the given ``name`` exists in the static symbol table
  bool has_static_symbol(const std::string& name) const;

  //! Get the static symbol from the given name
  const Symbol& get_static_symbol(const std::string& name) const;

  Symbol& get_static_symbol(const std::string& name);

  //! Return list of strings used by the ELF binrary.
  //!
  //! Basically we look for string in the ``.roadata``
  string_list_t strings(const size_t min_size = 5) const;

  //! Remove symbols with the given name in boths
  //!   * dynamic symbols
  //!   * static symbols
  //! @see remove_static_symbol, remove_dynamic_symbol
  void remove_symbol(const std::string& name);
  //void remove_symbol(Symbol* symbol);

  //!Remove static symbols with the given name
  void remove_static_symbol(const std::string& name);
  void remove_static_symbol(Symbol* symbol);

  //!Remove dynamic symbols with the given name
  void remove_dynamic_symbol(const std::string& name);

  //! Remove the given symbol from the dynamic symbol table.
  //!
  //! As a side effect, it will remove any ELF::Relocation
  //! that refer to this symbol and the SymbolVersion (if any)
  //! associated with this symbol
  void remove_dynamic_symbol(Symbol* symbol);

  //! Return the address of the given function name
  virtual uint64_t get_function_address(const std::string& func_name) const override;

  //! Return the address of the given function name
  //! @param func_name The function's name target
  //! @param demangled Use the demangled name
  uint64_t get_function_address(const std::string& func_name, bool demangled) const;

  //! Add a new section in the binary
  //!
  //! @param[in] section The section object to insert
  //! @param[in] loaded  Boolean value to indicate that sections's data must be loaded
  //!
  //! @return The section added. The `size` and the `virtual address` may have changed.
  Section& add(const Section& section, bool loaded = true);

  Section& extend(const Section& section, uint64_t size);

  //! Add a static symbol
  Symbol& add_static_symbol(const Symbol& symbol);

  //! Add a dynamic symbol with the associated SymbolVersion
  Symbol& add_dynamic_symbol(const Symbol& symbol, const SymbolVersion* version = nullptr);

  //! Create a symbol for the function at the given address and export it
  Symbol& add_exported_function(uint64_t address, const std::string& name = "");

  //! Add a library as dependency
  DynamicEntryLibrary& add_library(const std::string& library_name);

  //! Remove the given library
  void remove_library(const std::string& library_name);

  //! Get the library object (DynamicEntryLibrary) from the given name
  DynamicEntryLibrary& get_library(const std::string& library_name);

  //! Get the library object (DynamicEntryLibrary) from the given name
  const DynamicEntryLibrary& get_library(const std::string& library_name) const;

  //! Check if the given library name exists in the current binary
  bool has_library(const std::string& name) const;

  //! Add a new segment in the binary
  //!
  //! The segment is inserted at the end
  //! @warning We assume that the binary is not position independent
  //!
  //! @return The segment added. `Virtual address` and `File Offset` may have changed
  Segment& add(const Segment& segment, uint64_t base = 0);

  //! Replace the segment given in 2nd parameter with the segment given in the first one and return the updated segment.
  //!
  //! @warning .The ``original_segment`` is no longer valid after this function
  Segment& replace(const Segment& new_segment, const Segment& original_segment, uint64_t base = 0);

  Segment& extend(const Segment& segment, uint64_t size);


  //! Patch the content at virtual address @p address with @p patch_value
  //!
  //! @param[in] address Address to patch
  //! @param[in] patch_value Patch to apply
  //! @param[in] addr_type Specify if the address should be used as an absolute virtual address or an RVA
  virtual void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;


  //! Patch the address with the given value
  //!
  //! @param[in] address Address to patch
  //! @param[in] patch_value Patch to apply
  //! @param[in] size Size of the value in **bytes** (1, 2, ... 8)
  //! @param[in] addr_type Specify if the address should be used as an absolute virtual address or an RVA
  virtual void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t), LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;

  //! Patch the imported symbol with the ``address``
  //!
  //! @param[in] symbol Imported symbol to patch
  //! @param[in] address New address
  void patch_pltgot(const Symbol& symbol, uint64_t address);


  //! Patch the imported symbol's name with the ``address``
  //!
  //! @param[in] symbol_name Imported symbol's name to patch
  //! @param[in] address New address
  void patch_pltgot(const std::string& symbol_name, uint64_t address);


  //! Strip the binary by removing static symbols
  void strip(void);

  //! Remove a binary's section.
  //!
  //! We clear data used by this section and it's removed from
  //! section table
  virtual void remove_section(const std::string& name, bool clear = false) override;

  //! Reconstruct the binary object and write it in `filename`
  //! @param filename Path to write the reconstructed binary
  virtual void write(const std::string& filename) override;

  //! Reconstruct the binary object and return his content as bytes
  std::vector<uint8_t> raw(void);

  //! Convert a virtual address to an offset in the file
  uint64_t virtual_address_to_offset(uint64_t virtual_address) const;

  //! Convert the given offset into a virtual address.
  //!
  //! @param[in] offset The offset to convert.
  //! @param[in] slide If not 0, it will replace the default base address (if any)
  uint64_t offset_to_virtual_address(uint64_t offset, uint64_t slide = 0) const override;

  //! Check if the binary has been compiled with `-fpie -pie` flags
  //!
  //! To do so we check if there is a `PT_INTERP` segment and if
  //! the binary type is `ET_DYN` (Shared object)
  virtual bool is_pie(void) const override;

  //! Check if the binary uses ``NX`` protection
  virtual bool has_nx(void) const override;

  //! Return the @link ELF::Section Section @endlink
  //! from the @p offset
  const Section& section_from_offset(uint64_t offset) const;
  Section&       section_from_offset(uint64_t offset);

  //! Return the @link ELF::Section Section @endlink
  //! from the @p address
  const Section& section_from_virtual_address(uint64_t address) const;
  Section&       section_from_virtual_address(uint64_t address);

  //! Return the @link ELF::Segment Segment @endlink
  //! from the @p address
  const Segment& segment_from_virtual_address(uint64_t address) const;
  Segment&       segment_from_virtual_address(uint64_t address);

  //! Return the @link ELF::Segment Segment @endlink
  //! from the @p offset
  const Segment& segment_from_offset(uint64_t offset) const;
  Segment&       segment_from_offset(uint64_t offset);

  //! Return the **first** ELF::DynamicEntry associated with the given tag
  const DynamicEntry& get(DYNAMIC_TAGS tag) const;
  DynamicEntry&       get(DYNAMIC_TAGS tag);

  //! Return the **first** ELF::Segment associated with the given type
  const Segment& get(SEGMENT_TYPES type) const;
  Segment&       get(SEGMENT_TYPES type);

  //! Return the **first** ELF::Note associated with the given type
  const Note& get(NOTE_TYPES type) const;
  Note&       get(NOTE_TYPES type);

  //! Return the **first** ELF::Section associated with the given type
  const Section& get(ELF_SECTION_TYPES type) const;
  Section&       get(ELF_SECTION_TYPES type);

  //! Check if an ELF::DynamicEntry associated with the given tag
  //! exists.
  bool has(DYNAMIC_TAGS tag) const;

  //! Check if ELF::Segment associated with the given type
  //! exists.
  bool has(SEGMENT_TYPES type) const;

  //! Check if a ELF::Note associated with the given type
  //! exists.
  bool has(NOTE_TYPES type) const;

  //! Check if a ELF::Section associated with the given type
  //! exists.
  bool has(ELF_SECTION_TYPES type) const;

  //! Return the content located at virtual address
  virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address, uint64_t size,
      LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) const override;

  //! Method so that the ``visitor`` can visit us
  virtual void accept(LIEF::Visitor& visitor) const override;

  //! Apply the given permutation on the dynamic symbols table
  //!
  //! To avoid override by the ELF::Builder, one should set ELF::Builder::empties_gnuhash
  //! to ``true``
  void permute_dynamic_symbols(const std::vector<size_t>& permutation);

  virtual LIEF::Binary::functions_t ctor_functions(void) const override;
  LIEF::Binary::functions_t dtor_functions(void) const;

  LIEF::Binary::functions_t functions(void) const;

  //! ``true`` if the binary embed notes
  bool has_notes(void) const;

  //! Return the Note object if any
  //! @see has_note
  it_const_notes notes(void) const;

  it_notes notes(void);

  uint64_t eof_offset(void) const;

  //! True if data are present at the end of the binary
  bool has_overlay(void) const;

  //! Overlay data (if any)
  const overlay_t& overlay(void) const;

  void overlay(overlay_t overlay);

  size_t hash(const std::string& name);

  virtual ~Binary(void);

  virtual std::ostream& print(std::ostream& os) const override;

  bool operator==(const Binary& rhs) const;
  bool operator!=(const Binary& rhs) const;


  Binary& operator+=(const DynamicEntry& entry);
  Binary& operator+=(const Section& section);
  Binary& operator+=(const Segment& segment);
  Binary& operator+=(const Note& note);

  Binary& operator-=(const DynamicEntry& entry);
  Binary& operator-=(DYNAMIC_TAGS tag);

  Binary& operator-=(const Note& note);
  Binary& operator-=(NOTE_TYPES type);

  Segment&       operator[](SEGMENT_TYPES type);
  const Segment& operator[](SEGMENT_TYPES type) const;

  DynamicEntry&       operator[](DYNAMIC_TAGS tag);
  const DynamicEntry& operator[](DYNAMIC_TAGS tag) const;

  Note&       operator[](NOTE_TYPES type);
  const Note& operator[](NOTE_TYPES type) const;

  Section&       operator[](ELF_SECTION_TYPES type);
  const Section& operator[](ELF_SECTION_TYPES type) const;

  protected:
  Binary(void);

  //! Return an abstraction of binary's section: LIEF::Section
  virtual LIEF::sections_t         get_abstract_sections(void) override;

  virtual LIEF::Header             get_abstract_header(void) const override;

  virtual LIEF::Binary::functions_t get_abstract_exported_functions(void) const override;
  virtual LIEF::Binary::functions_t get_abstract_imported_functions(void) const override;
  virtual std::vector<std::string> get_abstract_imported_libraries(void) const override;
  virtual LIEF::symbols_t          get_abstract_symbols(void) override;
  virtual LIEF::relocations_t      get_abstract_relocations(void) override;

  template<ELF::ARCH ARCH>
  void patch_relocations(uint64_t from, uint64_t shift);

  template<class T>
  void patch_addend(Relocation& relocatio, uint64_t from, uint64_t shift);

  void shift_sections(uint64_t from, uint64_t shift);
  void shift_segments(uint64_t from, uint64_t shift);
  void shift_dynamic_entries(uint64_t from, uint64_t shift);
  void shift_symbols(uint64_t from, uint64_t shift);
  void shift_relocations(uint64_t from, uint64_t shift);

  template<class ELF_T>
  void fix_got_entries(uint64_t from, uint64_t shift);

  LIEF::Binary::functions_t eh_frame_functions(void) const;
  LIEF::Binary::functions_t armexid_functions(void) const;

  template<E_TYPE OBJECT_TYPE, bool note = false>
  Segment& add_segment(const Segment& segment, uint64_t base);

  template<SEGMENT_TYPES PT>
  Segment& extend_segment(const Segment& segment, uint64_t size);

  template<bool LOADED>
  Section& add_section(const Section& section);
  symbols_t static_dyn_symbols(void) const;

  std::string shstrtab_name(void) const;

  LIEF::Binary::functions_t tor_functions(DYNAMIC_TAGS tag) const;

  //! The binary type
  //! (i.e. `ELF32` or `ELF64`)
  ELF_CLASS type_;

  //! The binary's header as an object
  Header header_;

  //! The binary's sections if any
  sections_t sections_;

  //! The binary's segments if any
  segments_t segments_;

  //! A list of the diffrents dynamic entries.
  dynamic_entries_t dynamic_entries_;

  //! A list of dynamic symbols
  symbols_t dynamic_symbols_;

  //! A list of static symbols
  symbols_t static_symbols_;

  relocations_t relocations_;

  //! .gnu.version
  symbols_version_t symbol_version_table_;

  //! gnu.version_r
  symbols_version_requirement_t symbol_version_requirements_;

  //! .gnu.version_d
  symbols_version_definition_t  symbol_version_definition_;

  //! .gnu.hash
  GnuHash gnu_hash_;

  //! .note
  notes_t notes_;

  //! .hash
  SysvHash sysv_hash_;

  //! object used to manage segments/sections
  DataHandler::Handler* datahandler_{nullptr};

  std::string interpreter_;
  overlay_t overlay_;
};

}
}
#endif
