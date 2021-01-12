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
#ifndef LIEF_PE_BINARY_H_
#define LIEF_PE_BINARY_H_

#include <map>

#include "LIEF/PE/Header.hpp"
#include "LIEF/PE/OptionalHeader.hpp"
#include "LIEF/PE/DosHeader.hpp"
#include "LIEF/PE/RichHeader.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/Debug.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/signature/Signature.hpp"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {
class Parser;
class Builder;

//! Class which represent a PE binary object
class LIEF_API Binary : public LIEF::Binary {
  friend class Parser;
  friend class Builder;

  public:
  Binary(const std::string& name, PE_TYPE type);

  virtual ~Binary(void);

  //! Return `PE32` or `PE32+`
  PE_TYPE type(void) const;

  //! Convert Relative Virtual Address to offset
  //!
  //! We try to get the get section wich hold the given
  //! `RVA` and convert it to offset. If the section
  //! does not exist, we assume that `RVA` = `offset`
  uint64_t rva_to_offset(uint64_t RVA);

  //! Convert Virtual address to offset
  uint64_t va_to_offset(uint64_t VA);

  //! Find the section associated with the `offset`
  Section&       section_from_offset(uint64_t offset);
  const Section& section_from_offset(uint64_t offset) const;

  //! Find the section associated with the `virtual address`
  Section&       section_from_rva(uint64_t virtual_address);
  const Section& section_from_rva(uint64_t virtual_address) const;

  //! Return binary's sections
  it_sections       sections(void);
  it_const_sections sections(void) const;

  // =======
  // Headers
  // =======

  //! Return a reference to the PE::DosHeader object
  DosHeader&       dos_header(void);
  const DosHeader& dos_header(void) const;

  //! Return a reference to the PE::Header object
  Header&       header(void);
  const Header& header(void) const;

  //! Return a reference to the OptionalHeader object
  OptionalHeader&       optional_header(void);
  const OptionalHeader& optional_header(void) const;

  //! Compute the binary's virtual size.
  //! It should match with OptionalHeader::sizeof_image
  uint64_t virtual_size(void) const;

  //! Compute the size of all headers
  uint32_t sizeof_headers(void) const;

  //! Return a reference to the TLS object
  TLS&       tls(void);
  const TLS& tls(void) const;

  //! Set a TLS object in the current Binary
  void tls(const TLS& tls);

  //! Check if the current binary has a TLS object
  bool has_tls(void) const;

  //! Check if the current binary has imports
  //!
  //! @see Import
  bool has_imports(void) const;

  //! Check if the current binary conatains signatures
  bool has_signatures(void) const;

  //! Check if the current binary has exports.
  //!
  //! @see Export
  bool has_exports(void) const;

  //! Check if the current binary has resources
  bool has_resources(void) const;

  //! Check if the current binary has exceptions
  bool has_exceptions(void) const;

  //! Check if the current binary has relocations
  //!
  //! @see Relocation
  bool has_relocations(void) const;

  //! Check if the current binary has debugs
  bool has_debug(void) const;

  //! Check if the current binary has a load configuration
  bool has_configuration(void) const;

  //! Check if the current binary has been built has reproducible, replacing timestamps by a compile hash.
  //!
  //! @see Debug
  bool is_reproducible_build(void) const;

  //! Return the Signature object(s) if the bianry is signed
  it_const_signatures signatures(void) const;

  //! Verify the binary against the embedded signature(s) (if any)
  //! First, it checks that the embedded signatures are correct (c.f. Signature::check)
  //! and then it checks that the authentihash matches ContentInfo::digest
  //!
  //! One can tweak the verification process with the Signature::VERIFICATION_CHECKS flags
  //!
  //! @see LIEF::PE::Signature::check
  Signature::VERIFICATION_FLAGS verify_signature(
      Signature::VERIFICATION_CHECKS checks = Signature::VERIFICATION_CHECKS::DEFAULT) const;

  //! Verify the binary with the Signature object provided in the first parameter
  //! It can be used to verify a detached signature:
  //!
  //! \code{.cpp}
  //! result<Signature> detached = LIEF::PE::SignatureParser::parse("sig.pkcs7")
  //! if (detached) {
  //!   binary->verify_signature(detached.value());
  //! }
  //! \endcode
  Signature::VERIFICATION_FLAGS verify_signature(const Signature& sig,
      Signature::VERIFICATION_CHECKS checks = Signature::VERIFICATION_CHECKS::DEFAULT) const;

  //! Compute the authentihash according to the algorithm provided in the first
  //! parameter
  std::vector<uint8_t> authentihash(ALGORITHMS algo) const;

  //! Try to predict the RVA of the function `function` in the import library `library`
  //!
  //! @warning
  //! The value could be chang if imports change
  //!
  //! @note
  //! It should be used with:
  //! LIEF::PE::Builder::build_imports set to ``true``
  //!
  //! @param[in] library  Library name in which the function is located
  //! @param[in] function Function name
  //! @return The address of the function (``IAT``)  in the new import table
  uint32_t predict_function_rva(const std::string& library, const std::string& function);

  //! Return the Export object
  Export&       get_export(void);
  const Export& get_export(void) const;

  //! Return binary Symbols
  std::vector<Symbol>&       symbols(void);
  const std::vector<Symbol>& symbols(void) const;

  //! Return resources as a tree
  ResourceNode&                  resources(void);
  const ResourceNode&            resources(void) const;

  //! Set a new resource tree
  void set_resources(const ResourceDirectory& resource);

  //! Set a new resource tree
  void set_resources(const ResourceData& resource);

  //! Return the ResourcesManager (class to manage resources more easily than the tree one)
  ResourcesManager               resources_manager(void);
  const ResourcesManager         resources_manager(void) const;

  // ==========================
  // Methods to manage sections
  // ==========================

  //! Return binary's section from its name
  //!
  //! @param[in] name Name of the Section
  Section&       get_section(const std::string& name);
  const Section& get_section(const std::string& name) const;

  //! Return the section associated with import table
  const Section& import_section(void) const;
  Section&       import_section(void);

  //! Delete the section with the given name
  //!
  //! @param[in] name Name of section to delete
  //! @param[in] clear if ``true`` clear the section's content with 0 before removing (default: ``false``)
  virtual void remove_section(const std::string& name, bool clear = false) override;

  //! Remove the given section
  void remove(const Section& section, bool clear = false);

  //! Add a section to the binary and return the section added.
  Section& add_section(
      const Section& section,
      PE_SECTION_TYPES type = PE_SECTION_TYPES::UNKNOWN);

  // =============================
  // Methods to manage relocations
  // =============================

  it_relocations       relocations(void);
  it_const_relocations relocations(void) const;

  //! Add a @link PE::Relocation relocation @endlink
  Relocation& add_relocation(const Relocation& relocation);

  //! Remove all relocations
  void remove_all_relocations(void);

  // ===============================
  // Methods to manage DataDirectory
  // ===============================

  //! Return data directories in the binary
  it_data_directories       data_directories(void);
  it_const_data_directories data_directories(void) const;

  //! Return the DataDirectory with the given type (or index)
  DataDirectory&       data_directory(DATA_DIRECTORY index);
  const DataDirectory& data_directory(DATA_DIRECTORY index) const;

  bool has(DATA_DIRECTORY index) const;

  //! Return the debug_entries_t object
  debug_entries_t&       debug(void);
  const debug_entries_t& debug(void) const;

  //! Retrun the LoadConfiguration object
  const LoadConfiguration& load_configuration(void) const;
  LoadConfiguration& load_configuration(void);

  // =======
  // Overlay
  // =======

  //! Return the overlay content
  const std::vector<uint8_t>& overlay(void) const;
  std::vector<uint8_t>&       overlay(void);

  // ========
  // DOS Stub
  // ========

  //! Return the DOS stub content
  const std::vector<uint8_t>& dos_stub(void) const;
  std::vector<uint8_t>&       dos_stub(void);

  //! Update the DOS stub content
  void dos_stub(const std::vector<uint8_t>& content);

  // Rich Header
  // -----------

  //! Return a reference to the RichHeader object
  RichHeader&       rich_header(void);
  const RichHeader& rich_header(void) const;

  //! Set a RichHeader object in the current Binary
  void rich_header(const RichHeader& rich_header);

  //! Check if the current binary has a RichHeader object
  bool has_rich_header(void) const;

  // =========================
  // Methods to manage Imports
  // =========================

  //! return binary's @link PE::Import imports @endlink
  it_imports       imports(void);
  it_const_imports imports(void) const;

  //! Returns the PE::Import from the given name
  //!
  //! @param[in] import_name Name of the import
  Import&          get_import(const std::string& import_name);
  const Import&    get_import(const std::string& import_name) const;

  //! ``True`` if the binary import the given library name
  //!
  //! @param[in] import_name Name of the import
  bool has_import(const std::string& import_name) const;

  //! Add the function @p function of the library @p library
  //!
  //! @param[in] library library name of the function
  //! @param[in] function function's name from the library to import
  ImportEntry& add_import_function(const std::string& library, const std::string& function);

  //! add an imported library (i.e. `DLL`) to the binary
  Import& add_library(const std::string& name);

  //! Remove the library with the given `name`
  void remove_library(const std::string& name);

  //! Remove all libraries in the binary
  void remove_all_libraries(void);

  //! Hook an imported function
  //!
  //! When using this function, LIEF::PE::Builder::build_imports and LIEF::PE::Builder::patch_imports
  //! should be set to ``true``
  //!
  //! @param[in] function Function name to hook
  //! @param[in] address Address of the hook
  void hook_function(const std::string& function, uint64_t address);


  //! Hook an imported function
  //!
  //! When using this function, LIEF::PE::Builder::build_imports(true) and LIEF::PE::Builder::patch_imports
  //! should be set to ``true``
  //!
  //! @param[in] library  Library name in which the function is located
  //! @param[in] function Function name to hook
  //! @param[in] address  Address of the hook
  void hook_function(const std::string& library, const std::string& function, uint64_t address);

  //! Reconstruct the binary object and write it in  `filename`
  //!
  //! Rebuild a PE binary from the current Binary object.
  //! When rebuilding, import table and relocations are not rebuilt.
  virtual void write(const std::string& filename) override;

  virtual void accept(Visitor& visitor) const override;


  // LIEF Interface
  // ==============

  //! Patch the content at virtual address @p address with @p patch_value
  //!
  //! @param[in] address Address to patch
  //! @param[in] patch_value Patch to apply
  //! @param[in] addr_type Type of the Virtual address: VA or RVA. Default: Auto
  virtual void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;


  //! Patch the address with the given value
  //!
  //! @param[in] address Address to patch
  //! @param[in] patch_value Patch to apply
  //! @param[in] size Size of the value in **bytes** (1, 2, ... 8)
  //! @param[in] addr_type Type of the Virtual address: VA or RVA. Default: Auto
  virtual void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t), LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;

  //! Return the content located at virtual address
  //
  //! @param[in] virtual_address Virtual address of the data to retrieve
  //! @param[in] size Size in bytes of the data to retrieve
  //! @param[in] addr_type Type of the Virtual address: VA or RVA. Default: Auto
  virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address, uint64_t size,
      LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) const override;

  //! Return the binary's entrypoint
  virtual uint64_t entrypoint(void) const override;

  //! Check if the binary is position independent
  virtual bool is_pie(void) const override;

  //! Check if the binary uses ``NX`` protection
  virtual bool has_nx(void) const override;

  virtual LIEF::Binary::functions_t ctor_functions(void) const override;

  //! **All** functions found in the binary
  LIEF::Binary::functions_t functions(void) const;

  //! Functions found in the Exception table directory
  LIEF::Binary::functions_t exception_functions(void) const;

  bool operator==(const Binary& rhs) const;
  bool operator!=(const Binary& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  private:
  Binary(void);

  //! Make space between the last section header and the beginning of the
  //! content of first section
  void make_space_for_new_section(void);

  //! Return binary's symbols as LIEF::Symbol
  virtual LIEF::symbols_t  get_abstract_symbols(void) override;

  virtual LIEF::Header     get_abstract_header(void) const override;

  //! Return binary's section as LIEF::Section
  virtual LIEF::sections_t get_abstract_sections(void) override;

  virtual LIEF::relocations_t get_abstract_relocations(void) override;

  virtual LIEF::Binary::functions_t get_abstract_exported_functions(void) const override;
  virtual LIEF::Binary::functions_t get_abstract_imported_functions(void) const override;
  virtual std::vector<std::string> get_abstract_imported_libraries(void) const override;

  void update_lookup_address_table_offset(void);
  void update_iat(void);

  PE_TYPE        type_;
  DosHeader      dos_header_;
  RichHeader     rich_header_;
  Header         header_;
  OptionalHeader optional_header_;

  int32_t available_sections_space_;

  bool has_rich_header_;
  bool has_tls_;
  bool has_imports_;
  bool has_exports_;
  bool has_resources_;
  bool has_exceptions_;
  bool has_relocations_;
  bool has_debug_;
  bool has_configuration_;
  bool is_reproducible_build_;

  signatures_t         signatures_;
  TLS                  tls_;
  sections_t           sections_;
  data_directories_t   data_directories_;
  symbols_t            symbols_;
  strings_table_t      strings_table_;
  relocations_t        relocations_;
  ResourceNode*        resources_;
  imports_t            imports_;
  Export               export_;
  debug_entries_t      debug_;
  uint64_t overlay_offset_ = 0;
  std::vector<uint8_t> overlay_;
  std::vector<uint8_t> dos_stub_;
  std::vector<uint8_t> section_offset_padding_;

  LoadConfiguration*   load_configuration_{nullptr};

  std::map<std::string, std::map<std::string, uint64_t>> hooks_;
};

}
}
#endif
