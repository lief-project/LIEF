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
#ifndef LIEF_PE_BINARY_H
#define LIEF_PE_BINARY_H

#include "LIEF/PE/Header.hpp"
#include "LIEF/PE/OptionalHeader.hpp"
#include "LIEF/PE/DosHeader.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/DelayImport.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/signature/Signature.hpp"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/visibility.h"

namespace LIEF {

//! Namespace related to the LIEF's PE module
namespace PE {
class Builder;
class CodeViewPDB;
class Debug;
class Export;
class LoadConfiguration;
class Parser;
class Relocation;
class ResourceData;
class ResourceDirectory;
class ResourceNode;
class RichHeader;
class TLS;

//! Class which represents a PE binary
//! This is the main interface to manage and modify a PE executable
class LIEF_API Binary : public LIEF::Binary {
  friend class Parser;
  friend class Builder;

  public:
  //! Internal container for storing PE's Section
  using sections_t = std::vector<std::unique_ptr<Section>>;

  //! Iterator that outputs Section& object
  using it_sections = ref_iterator<sections_t&, Section*>;

  //! Iterator that outputs const Section& object
  using it_const_sections = const_ref_iterator<const sections_t&, const Section*>;

  //! Internal container for storing PE's DataDirectory
  using data_directories_t = std::vector<std::unique_ptr<DataDirectory>>;

  //! Iterator that outputs DataDirectory&
  using it_data_directories = ref_iterator<data_directories_t&, DataDirectory*>;

  //! Iterator that outputs const DataDirectory&
  using it_const_data_directories = const_ref_iterator<const data_directories_t&, const DataDirectory*>;

  //! Internal container for storing PE's Relocation
  using relocations_t = std::vector<std::unique_ptr<Relocation>>;

  //! Iterator that outputs Relocation&
  using it_relocations = ref_iterator<relocations_t&, Relocation*>;

  //! Iterator that outputs const Relocation&
  using it_const_relocations = const_ref_iterator<const relocations_t&, const Relocation*>;

  //! Internal container for storing PE's Import
  using imports_t = std::vector<Import>;

  //! Iterator that output Import&
  using it_imports = ref_iterator<imports_t&>;

  //! Iterator that outputs const Import&
  using it_const_imports = const_ref_iterator<const imports_t&>;

  //! Internal container for storing PE's DelayImport
  using delay_imports_t = std::vector<DelayImport>;

  //! Iterator that output DelayImport&
  using it_delay_imports = ref_iterator<delay_imports_t&>;

  //! Iterator that outputs const DelayImport&
  using it_const_delay_imports = const_ref_iterator<const delay_imports_t&>;

  //! Internal container for storing Debug information
  using debug_entries_t = std::vector<std::unique_ptr<Debug>>;

  //! Iterator that outputs Debug&
  using it_debug_entries = ref_iterator<debug_entries_t&, Debug*>;

  //! Iterator that outputs const Debug&
  using it_const_debug_entries = const_ref_iterator<const debug_entries_t&, const Debug*>;

  //! Internal container for storing COFF Symbols
  using symbols_t = std::vector<Symbol>;

  //! Iterator that outputs Symbol&
  using it_symbols = ref_iterator<symbols_t&>;

  //! Iterator that outputs const Symbol&
  using it_const_symbols = const_ref_iterator<const symbols_t&>;

  //! Internal container for storing strings
  using strings_table_t = std::vector<std::string>;

  //! Iterator that outputs std::string&
  using it_strings_table = ref_iterator<strings_table_t&>;

  //! Iterator that outputs const std::string&
  using it_const_strings_table = const_ref_iterator<const strings_table_t&>;

  //! Internal container for storing PE's authenticode Signature
  using signatures_t = std::vector<Signature>;

  //! Iterator that outputs Signature&
  using it_signatures = ref_iterator<signatures_t&>;

  //! Iterator that outputs const Signature&
  using it_const_signatures = const_ref_iterator<const signatures_t&>;

  Binary(PE_TYPE type);

  ~Binary() override;

  //! Return `PE32` or `PE32+`
  PE_TYPE type() const {
    return type_;
  }

  //! Convert a Relative Virtual Address into an offset
  //!
  //! The conversion is performed by looking for the section that
  //! encompasses the provided RVA.
  uint64_t rva_to_offset(uint64_t RVA) const;

  //! Convert the **absolute** virtual address into an offset.
  //! @see rva_to_offset
  uint64_t va_to_offset(uint64_t VA) const;

  //! Convert the given offset into a virtual address.
  //!
  //! @param[in] offset The offset to convert.
  //! @param[in] slide  If not 0, it will replace the default base address (if any)
  result<uint64_t> offset_to_virtual_address(uint64_t offset, uint64_t slide = 0) const override;

  //! Return binary's imagebase. ``0`` if not relevant
  //!
  //! The value is the same as those returned by OptionalHeader::imagebase
  uint64_t imagebase() const override {
    return optional_header().imagebase();
  }

  //! Find the section associated that encompasses the given offset.
  //!
  //! If no section can be found, return a nullptr
  Section* section_from_offset(uint64_t offset);
  const Section* section_from_offset(uint64_t offset) const;

  //! Find the section associated that encompasses the given RVA.
  //!
  //! If no section can be found, return a nullptr
  Section* section_from_rva(uint64_t virtual_address);
  const Section* section_from_rva(uint64_t virtual_address) const;

  //! Return an iterator over the PE's Section
  it_sections sections() {
    return sections_;
  }

  it_const_sections sections() const {
    return sections_;
  }

  //! Return a reference to the PE::DosHeader object
  DosHeader& dos_header() {
    return dos_header_;
  }

  const DosHeader& dos_header() const {
    return dos_header_;
  }

  //! Return a reference to the PE::Header object
  Header& header() {
    return header_;
  }

  const Header& header() const {
    return header_;
  }

  //! Header that follows the header(). It is named optional from the COFF
  //! specfication but it is mandatory in a PE file.
  OptionalHeader& optional_header() {
    return optional_header_;
  }

  const OptionalHeader& optional_header() const {
    return optional_header_;
  }

  //! Re-compute the value of OptionalHeader::checksum.
  //! If both values do not match, it could mean that the binary has been modified
  //! after the compilation.
  //!
  //! This value is computed by LIEF for the current binary object.
  uint32_t compute_checksum() const;

  //! Compute the binary's virtual size.
  //! It should match OptionalHeader::sizeof_image
  uint64_t virtual_size() const;

  //! Compute the size of all the headers
  uint32_t sizeof_headers() const;

  //! Return a reference to the TLS object
  TLS* tls() {
    return tls_.get();
  }

  const TLS* tls() const {
    return tls_.get();
  }

  //! Set a TLS object in the current Binary
  void tls(const TLS& tls);

  //! Check if the current binary has a TLS object
  bool has_tls() const {
    return tls_ != nullptr;
  }

  //! Check if the current binary contains imports
  //!
  //! @see Import
  bool has_imports() const {
    return !imports_.empty();
  }

  //! Check if the current binary contains signatures
  //!
  //! @see signatures
  bool has_signatures() const {
    return !signatures_.empty();
  }

  //! Check if the current binary has exports.
  //!
  //! @see Export
  bool has_exports() const {
    return export_ != nullptr;
  }

  //! Check if the current binary has resources
  bool has_resources() const {
    return resources_ != nullptr;
  }

  //! Check if the current binary has exceptions
  bool has_exceptions() const;

  //! Check if the current binary has relocations
  //!
  //! @see Relocation
  bool has_relocations() const {
    return !relocations_.empty();
  }

  //! Check if the current binary contains debug information
  bool has_debug() const {
    return !debug_.empty();
  }

  //! Check if the current binary has a load configuration
  bool has_configuration() const {
    return load_configuration_ != nullptr;
  }

  //! Check if the current binary is *reproducible build*, replacing timestamps by a compile hash.
  //!
  //! @see Repro
  bool is_reproducible_build() const;

  //! Return an iterator over the Signature object(s) if the binary is signed
  it_const_signatures signatures() const {
    return signatures_;
  }

  it_signatures signatures() {
    return signatures_;
  }

  //! Verify the binary against the embedded signature(s) (if any)
  //! First, it checks that the embedded signatures are correct (c.f. Signature::check)
  //! and then, it checks that the authentihash matches ContentInfo::digest
  //!
  //! One can tweak the verification process with the Signature::VERIFICATION_CHECKS flags
  //!
  //! @see LIEF::PE::Signature::check
  Signature::VERIFICATION_FLAGS verify_signature(
      Signature::VERIFICATION_CHECKS checks = Signature::VERIFICATION_CHECKS::DEFAULT) const;

  //! Verify the binary with the Signature object provided in the first parameter.
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
  Export* get_export() {
    return export_.get();
  }

  const Export* get_export() const {
    return export_.get();
  }

  //! Return binary Symbols
  std::vector<Symbol>& symbols() {
    return symbols_;
  }

  const std::vector<Symbol>& symbols() const {
    return symbols_;
  }

  //! Return resources as a tree or a nullptr if there is no resources
  ResourceNode* resources() {
    return resources_.get();
  }

  const ResourceNode* resources() const {
    return resources_.get();
  }

  //! Set a new resource tree
  void set_resources(const ResourceDirectory& resource);

  //! Set a new resource tree
  void set_resources(const ResourceData& resource);

  //! Return the ResourcesManager (class to manage resources more easily than the tree one)
  result<ResourcesManager> resources_manager() const;

  //! Return binary's section from its name.
  //! If the secion can't be found, return a nullptr
  //!
  //! @param[in] name Name of the Section
  Section* get_section(const std::string& name);
  const Section* get_section(const std::string& name) const;

  //! Return the section associated with import table or a
  //! nullptr if the binary does not have an import table
  const Section* import_section() const;
  Section*       import_section();

  //! Delete the section with the given name
  //!
  //! @param[in] name    Name of section to delete
  //! @param[in] clear   if ``true`` clear the section's content with 0
  //!                    before removing (default: ``false``)
  void remove_section(const std::string& name, bool clear = false) override;

  //! Remove the given section
  //!
  //! @see remove_section
  void remove(const Section& section, bool clear = false);

  //! Add a section to the binary and return the section added.
  Section* add_section(const Section& section,
                       PE_SECTION_TYPES type = PE_SECTION_TYPES::UNKNOWN);

  //! Return an iterator over the PE's Relocation
  it_relocations relocations() {
    return relocations_;
  }

  it_const_relocations relocations() const {
    return relocations_;
  }

  //! Add a PE::Relocation
  Relocation& add_relocation(const Relocation& relocation);

  //! Remove all the relocations
  void remove_all_relocations();

  //! Return an iterator over the DataDirectory present in the Binary
  it_data_directories data_directories() {
    return data_directories_;
  }

  it_const_data_directories data_directories() const {
    return data_directories_;
  }

  //! Return the DataDirectory with the given type (or index)
  DataDirectory* data_directory(DataDirectory::TYPES type);
  const DataDirectory* data_directory(DataDirectory::TYPES type) const;

  //! Check if the current binary has the given DataDirectory::TYPES
  bool has(DataDirectory::TYPES type) const {
    return data_directory(type) != nullptr;
  }

  //! Return an iterator over the Debug entries
  it_debug_entries debug() {
    return debug_;
  }

  it_const_debug_entries debug() const {
    return debug_;
  }

  //! Return the CodeViewPDB object if present
  const CodeViewPDB* codeview_pdb() const;

  //! Retrun the LoadConfiguration object or a nullptr
  //! if the binary does not use the LoadConfiguration
  const LoadConfiguration* load_configuration() const {
    return load_configuration_.get();
  }

  LoadConfiguration* load_configuration() {
    return load_configuration_.get();
  }

  //! Return the overlay content
  span<const uint8_t> overlay() const {
    return overlay_;
  }

  span<uint8_t> overlay() {
    return overlay_;
  }

  //! Return the original overlay offset
  uint64_t overlay_offset() const {
    return overlay_offset_;
  }

  //! Return the DOS stub content
  span<const uint8_t> dos_stub() const {
    return dos_stub_;
  }

  span<uint8_t> dos_stub() {
    return dos_stub_;
  }

  //! Update the DOS stub content
  void dos_stub(std::vector<uint8_t> content) {
    dos_stub_ = std::move(content);
  }

  // Rich Header
  // -----------

  //! Return a reference to the RichHeader object
  RichHeader* rich_header() {
    return rich_header_.get();
  }

  const RichHeader* rich_header() const {
    return rich_header_.get();
  }

  //! Set a RichHeader object in the current Binary
  void rich_header(const RichHeader& rich_header);

  //! Check if the current binary has a RichHeader object
  bool has_rich_header() const {
    return rich_header_ != nullptr;
  }

  //! Return an iterator over the binary imports
  it_imports imports() {
    return imports_;
  }

  it_const_imports imports() const {
    return imports_;
  }

  //! Returns the PE::Import from the given name. If it can't be
  //! found, return a nullptr
  //!
  //! @param[in] import_name Name of the import
  Import* get_import(const std::string& import_name);
  const Import* get_import(const std::string& import_name) const;

  //! ``True`` if the binary imports the given library name
  //!
  //! @param[in] import_name Name of the import
  bool has_import(const std::string& import_name) const {
    return get_import(import_name) != nullptr;
  }

  //! Check if the current binary contains delay imports
  //!
  //! @see DelayImport
  //! @see has_import
  bool has_delay_imports() const {
    return !delay_imports_.empty();
  }

  //! Return an iterator over the binary's delay imports
  it_delay_imports delay_imports() {
    return delay_imports_;
  }

  it_const_delay_imports delay_imports() const {
    return delay_imports_;
  }

  //! Returns the PE::DelayImport from the given name. If it can't be
  //! found, return a nullptr
  //!
  //! @param[in] import_name Name of the delay import
  DelayImport* get_delay_import(const std::string& import_name);
  const DelayImport* get_delay_import(const std::string& import_name) const;


  //! ``True`` if the binary delay-imports the given library name
  //!
  //! @param[in] import_name Name of the delay import
  bool has_delay_import(const std::string& import_name) const {
    return get_delay_import(import_name) != nullptr;
  }


  //! Add the function @p function of the library @p library.
  //! If the function fails, it returns a nullptr
  //!
  //! @param[in] library  Library name of the function
  //! @param[in] function Function's name from the library to import
  ImportEntry* add_import_function(const std::string& library, const std::string& function);

  //! Add an imported library (i.e. `DLL`) to the binary
  Import& add_library(const std::string& name) {
    imports_.emplace_back(name);
    return imports_.back();
  }

  //! Remove the library with the given `name`
  void remove_library(const std::string& name);

  //! Remove all libraries in the binary
  void remove_all_libraries() {
    imports_.clear();
  }

  //! Reconstruct the binary object and write the raw PE in `filename`
  //!
  //! Rebuild a PE binary from the current Binary object.
  //! When rebuilding, import table and relocations are not rebuilt.
  void write(const std::string& filename) override;

  //! Reconstruct the binary object and write the raw PE in `os` stream
  //!
  //! Rebuild a PE binary from the current Binary object.
  //! When rebuilding, import table and relocations are not rebuilt.
  void write(std::ostream& os) override;

  void accept(Visitor& visitor) const override;

  //! Patch the content at virtual address @p address with @p patch_value
  //!
  //! @param[in] address      Address to patch
  //! @param[in] patch_value  Patch to apply
  //! @param[in] addr_type    Type of the Virtual address: VA or RVA. Default: Auto
  void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value,
                     LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;


  //! Patch the address with the given value
  //!
  //! @param[in] address        Address to patch
  //! @param[in] patch_value    Patch to apply
  //! @param[in] size           Size of the value in **bytes** (1, 2, ... 8)
  //! @param[in] addr_type      Type of the Virtual address: VA or RVA. Default: Auto
  void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t),
                     LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;

  //! Return the content located at the provided virtual address
  //!
  //! @param[in] virtual_address    Virtual address of the data to retrieve
  //! @param[in] size               Size in bytes of the data to retrieve
  //! @param[in] addr_type          Type of the Virtual address: VA or RVA. Default: Auto
  span<const uint8_t> get_content_from_virtual_address(
      uint64_t virtual_address, uint64_t size,
      Binary::VA_TYPES addr_type = Binary::VA_TYPES::AUTO) const override;

  //! Return the binary's entrypoint (It is the same value as OptionalHeader::addressof_entrypoint
  uint64_t entrypoint() const override {
    return optional_header_.imagebase() + optional_header_.addressof_entrypoint();
  }

  //! Check if the binary is position independent
  bool is_pie() const override {
    return optional_header_.has(OptionalHeader::DLL_CHARACTERISTICS::DYNAMIC_BASE);
  }

  //! Check if the binary uses ``NX`` protection
  bool has_nx() const override {
    return optional_header_.has(OptionalHeader::DLL_CHARACTERISTICS::NX_COMPAT);
  }

  //! Return the list of the binary constructors.
  //!
  //! In a PE file, we consider a constructors as a callback in the TLS object
  LIEF::Binary::functions_t ctor_functions() const override;

  //! **All** functions found in the binary
  LIEF::Binary::functions_t functions() const;

  //! Functions found in the Exception table directory
  LIEF::Binary::functions_t exception_functions() const;

  static bool classof(const LIEF::Binary* bin) {
    return bin->format() == Binary::FORMATS::PE;
  }

  std::ostream& print(std::ostream& os) const override;

  private:
  Binary();

  //! Make space between the last section header and the beginning of the
  //! content of first section
  void make_space_for_new_section();

  //! Return binary's symbols as LIEF::Symbol
  LIEF::Binary::symbols_t get_abstract_symbols() override;

  LIEF::Header get_abstract_header() const override;

  //! Return binary's section as LIEF::Section
  LIEF::Binary::sections_t get_abstract_sections() override;

  LIEF::Binary::relocations_t get_abstract_relocations() override;

  LIEF::Binary::functions_t get_abstract_exported_functions() const override;
  LIEF::Binary::functions_t get_abstract_imported_functions() const override;
  std::vector<std::string> get_abstract_imported_libraries() const override;

  void update_lookup_address_table_offset();
  void update_iat();

  PE_TYPE        type_ = PE_TYPE::PE32_PLUS;
  DosHeader      dos_header_;
  Header         header_;
  OptionalHeader optional_header_;

  int32_t available_sections_space_ = 0;

  signatures_t signatures_;
  sections_t           sections_;
  data_directories_t   data_directories_;
  symbols_t            symbols_;
  strings_table_t      strings_table_;
  relocations_t        relocations_;
  imports_t            imports_;
  delay_imports_t      delay_imports_;
  debug_entries_t      debug_;
  uint64_t overlay_offset_ = 0;
  std::vector<uint8_t> overlay_;
  std::vector<uint8_t> dos_stub_;
  std::vector<uint8_t> section_offset_padding_;

  std::unique_ptr<RichHeader> rich_header_;
  std::unique_ptr<Export> export_;
  std::unique_ptr<ResourceNode> resources_;
  std::unique_ptr<TLS> tls_;
  std::unique_ptr<LoadConfiguration> load_configuration_;
};

}
}
#endif
