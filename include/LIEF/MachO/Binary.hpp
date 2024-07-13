
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
#ifndef LIEF_MACHO_BINARY_H
#define LIEF_MACHO_BINARY_H

#include <vector>
#include <map>
#include <memory>

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/iterators.hpp"
#include "LIEF/MachO/Header.hpp"
#include "LIEF/errors.hpp"

namespace LIEF {

namespace objc {
class Metadata;
}

//! Namespace related to the LIEF's Mach-O module
namespace MachO {

class BinaryParser;
class BuildVersion;
class Builder;
class CodeSignature;
class CodeSignatureDir;
class DataInCode;
class DyldChainedFixups;
class DyldEnvironment;
class DyldExportsTrie;
class DyldInfo;
class DylibCommand;
class DylinkerCommand;
class DynamicSymbolCommand;
class EncryptionInfo;
class ExportInfo;
class FunctionStarts;
class Header;
class LinkerOptHint;
class MainCommand;
class Parser;
class RPathCommand;
class Relocation;
class Section;
class SegmentCommand;
class SegmentSplitInfo;
class SourceVersion;
class SubFramework;
class Symbol;
class SymbolCommand;
class ThreadCommand;
class TwoLevelHints;
class UUIDCommand;
class VersionMin;

//! Class which represents a MachO binary
class LIEF_API Binary : public LIEF::Binary  {

  friend class Parser;
  friend class BinaryParser;
  friend class Builder;
  friend class DyldInfo;

  public:
  struct range_t {
    uint64_t start = 0;
    uint64_t end   = 0;
  };

  //! Internal container for storing Mach-O LoadCommand
  using commands_t = std::vector<std::unique_ptr<LoadCommand>>;

  //! Iterator that outputs LoadCommand&
  using it_commands = ref_iterator<commands_t&, LoadCommand*>;

  //! Iterator that outputs const LoadCommand&
  using it_const_commands = const_ref_iterator<const commands_t&, LoadCommand*>;

  //! Internal container for storing Mach-O Symbol
  using symbols_t = std::vector<std::unique_ptr<Symbol>>;

  //! Iterator that outputs Symbol&
  using it_symbols = ref_iterator<symbols_t&, Symbol*>;

  //! Iterator that outputs const Symbol&
  using it_const_symbols = const_ref_iterator<const symbols_t&, const Symbol*>;

  //! Iterator that outputs exported Symbol&
  using it_exported_symbols = filter_iterator<symbols_t&, Symbol*>;

  //! Iterator that outputs exported const Symbol&
  using it_const_exported_symbols = const_filter_iterator<const symbols_t&, const Symbol*>;

  //! Iterator that outputs imported Symbol&
  using it_imported_symbols = filter_iterator<symbols_t&, Symbol*>;

  //! Iterator that outputs imported const Symbol&
  using it_const_imported_symbols = const_filter_iterator<const symbols_t&, const Symbol*>;

  //! Internal container for caching Mach-O Section
  using sections_cache_t = std::vector<Section*>;

  //! Iterator that outputs Section&
  using it_sections = ref_iterator<sections_cache_t&>;

  //! Iterator that outputs const Section&
  using it_const_sections = const_ref_iterator<const sections_cache_t&>;

  //! Internal container for storing Mach-O SegmentCommand
  using segments_cache_t = std::vector<SegmentCommand*>;

  //! Iterator that outputs SegmentCommand&
  using it_segments = ref_iterator<segments_cache_t&>;

  //! Iterator that outputs const SegmentCommand&
  using it_const_segments = const_ref_iterator<const segments_cache_t&>;

  //! Internal container for storing Mach-O DylibCommand
  using libraries_cache_t = std::vector<DylibCommand*>;

  //! Iterator that outputs DylibCommand&
  using it_libraries = ref_iterator<libraries_cache_t&>;

  //! Iterator that outputs const DylibCommand&
  using it_const_libraries = const_ref_iterator<const libraries_cache_t&>;

  //! Internal container for storing Mach-O Fileset Binary
  using fileset_binaries_t = std::vector<std::unique_ptr<Binary>>;

  //! Iterator that outputs Binary&
  using it_fileset_binaries = ref_iterator<fileset_binaries_t&, Binary*>;

  //! Iterator that outputs const Binary&
  using it_const_fileset_binaries = const_ref_iterator<const fileset_binaries_t&, Binary*>;

  struct KeyCmp {
    bool operator() (const Relocation* lhs, const Relocation* rhs) const;
  };

  //! Internal container that store all the relocations
  //! found in a Mach-O. The relocations are actually owned
  //! by Section & SegmentCommand and these references are used for convenience
  using relocations_t = std::set<Relocation*, KeyCmp>;

  //! Iterator which outputs Relocation&
  using it_relocations = ref_iterator<relocations_t&, Relocation*>;

  //! Iterator which outputs const Relocation&
  using it_const_relocations = const_ref_iterator<const relocations_t&, const Relocation*>;

  //! Iterator which outputs RPathCommand&
  using it_rpaths = filter_iterator<commands_t&, RPathCommand*>;

  //! Iterator which outputs const RPathCommand&
  using it_const_rpaths = const_filter_iterator<const commands_t&, const RPathCommand*>;

  public:
  Binary(const Binary&) = delete;
  Binary& operator=(const Binary&) = delete;

  //! Return a reference to the MachO::Header
  Header& header() {
    return header_;
  }

  const Header& header() const {
    return header_;
  }

  //! Return an iterator over the MachO LoadCommand present
  //! in the binary
  it_commands commands() {
    return commands_;
  }

  it_const_commands commands() const {
    return commands_;
  }

  //! Return an iterator over the MachO::Binary associated
  //! with the LoadCommand::TYPE::FILESET_ENTRY commands
  it_fileset_binaries filesets() {
    return filesets_;
  }

  it_const_fileset_binaries filesets() const {
    return filesets_;
  }

  //! Return binary's @link MachO::Symbol symbols @endlink
  it_symbols symbols() {
    return symbols_;
  }
  it_const_symbols symbols() const {
    return symbols_;
  }

  //! Check if a symbol with the given name exists
  bool has_symbol(const std::string& name) const {
    return get_symbol(name) != nullptr;
  }

  //! Return Symbol from the given name. If the symbol does not
  //! exists, it returns a null pointer
  const Symbol* get_symbol(const std::string& name) const;
  Symbol* get_symbol(const std::string& name);

  //! Check if the given symbol is exported
  static bool is_exported(const Symbol& symbol);

  //! Return binary's exported symbols (iterator over LIEF::MachO::Symbol)
  it_exported_symbols exported_symbols() {
    return {symbols_, [] (const std::unique_ptr<Symbol>& symbol) {
      return is_exported(*symbol); }
    };
  }
  it_const_exported_symbols exported_symbols() const {
    return {symbols_, [] (const std::unique_ptr<Symbol>& symbol) {
      return is_exported(*symbol);
    }};
  }

  //! Check if the given symbol is an imported one
  static bool is_imported(const Symbol& symbol);

  //! Return binary's imported symbols (iterator over LIEF::MachO::Symbol)
  it_imported_symbols imported_symbols() {
    return {symbols_, [] (const std::unique_ptr<Symbol>& symbol) {
      return is_imported(*symbol);
    }};
  }

  it_const_imported_symbols imported_symbols() const {
    return {symbols_, [] (const std::unique_ptr<Symbol>& symbol) {
      return is_imported(*symbol);
    }};
  }

  //! Return binary imported libraries (MachO::DylibCommand)
  it_libraries libraries() {
    return libraries_;
  }

  it_const_libraries libraries() const {
    return libraries_;
  }

  //! Return an iterator over the SegmentCommand
  it_segments segments() {
    return segments_;
  }
  it_const_segments segments() const {
    return segments_;
  }

  //! Return an iterator over the MachO::Section
  it_sections sections() {
    return sections_;
  }
  it_const_sections sections() const {
    return sections_;
  }

  //! Return an iterator over the MachO::Relocation
  it_relocations       relocations();
  it_const_relocations relocations() const;

  //! Reconstruct the binary object and write the result in the given `filename`
  //!
  //! @param filename Path to write the reconstructed binary
  void write(const std::string& filename) override;

  //! Reconstruct the binary object and write the result in the given `os` stream
  //!
  //! @param os Output stream to write the reconstructed binary
  void write(std::ostream& os) override;

  //! Reconstruct the binary object and return its content as bytes
  std::vector<uint8_t> raw();

  //! Check if the current binary has the given MachO::LoadCommand::TYPE
  bool has(LoadCommand::TYPE type) const;

  //! Return the LoadCommand associated with the given LoadCommand::TYPE
  //! or a nullptr if the command can't be found.
  const LoadCommand* get(LoadCommand::TYPE type) const;
  LoadCommand* get(LoadCommand::TYPE type);

  //! Insert a new LoadCommand
  LoadCommand* add(const LoadCommand& command);

  //! Insert a new LoadCommand at the specified ``index``
  LoadCommand* add(const LoadCommand& command, size_t index);

  //! Insert the given DylibCommand
  LoadCommand* add(const DylibCommand& library);

  //! Add a new LC_SEGMENT command from the given SegmentCommand
  LoadCommand* add(const SegmentCommand& segment);

  //! Insert a new shared library through a ``LC_LOAD_DYLIB`` command
  LoadCommand* add_library(const std::string& name);

  //! Add a new MachO::Section in the __TEXT segment
  Section* add_section(const Section& section);

  //! Add a section in the given MachO::SegmentCommand.
  //!
  //! @warning This method may corrupt the file if the segment is not the first one
  //!          nor the last one
  Section* add_section(const SegmentCommand& segment, const Section& section);

  //! Remove the section with the name provided in the first parameter.
  //!
  //! @param name     Name of the MachO::Section to remove
  //! @param clear    If ``true`` clear the content of the section before removing
  void remove_section(const std::string& name, bool clear = false) override;

  //! Remove the section from the segment with the name
  //! given in the first parameter and with the section's name provided in the
  //! second parameter
  //!
  //! @param segname     Name of the MachO::Segment
  //! @param secname     Name of the MachO::Section to remove
  //! @param clear       If ``true`` clear the content of the section before removing
  void remove_section(const std::string& segname, const std::string& secname, bool clear = false);

  //! Remove the given LoadCommand
  bool remove(const LoadCommand& command);

  //! Remove **all** LoadCommand with the given type (MachO::LoadCommand::TYPE)
  bool remove(LoadCommand::TYPE type);

  //! Remove the Load Command at the provided ``index``
  bool remove_command(size_t index);

  //! Remove the LC_SIGNATURE command
  bool remove_signature();

  //! Extend the **size** of the given LoadCommand
  bool extend(const LoadCommand& command, uint64_t size);

  //! Extend the **content** of the given SegmentCommand
  bool extend_segment(const SegmentCommand& segment, size_t size);

  //! Remove the ``PIE`` flag
  bool disable_pie();

  //! Return the binary's imagebase. ``0`` if not relevant
  uint64_t imagebase() const override;

  //! Size of the binary in memory when mapped by the loader (``dyld``)
  uint64_t virtual_size() const;

  //! Return the binary's loader (e.g. ``/usr/lib/dyld``) or an
  //! empty string if the binary does not use a loader/linker
  std::string loader() const;

  //! Check if a section with the given name exists
  bool has_section(const std::string& name) const {
    return get_section(name) != nullptr;
  }

  //! Return the section from the given name of a nullptr
  //! if the section can't be found.
  Section* get_section(const std::string& name);

  //! Return the section from the given name or a nullptr
  //! if the section can't be found
  const Section* get_section(const std::string& name) const;

  //! Return the section from the segment with the name
  //! given in the first parameter and with the section's name provided in the
  //! second parameter. If the section cannot be found, it returns a nullptr
  Section* get_section(const std::string& segname, const std::string& secname);

  const Section* get_section(const std::string& segname, const std::string& secname) const;

  //! Check if a segment with the given name exists
  bool has_segment(const std::string& name) const {
    return get_segment(name) != nullptr;
  }

  //! Return the segment from the given name
  const SegmentCommand* get_segment(const std::string& name) const;

  //! Return the segment from the given name
  SegmentCommand* get_segment(const std::string& name);

  //! Remove the symbol with the given name
  bool remove_symbol(const std::string& name);

  //! Remove the given symbol
  bool remove(const Symbol& sym);

  //! Check if the given symbol can be safely removed.
  bool can_remove(const Symbol& sym) const;

  //! Check if the MachO::Symbol with the given name can be safely removed.
  bool can_remove_symbol(const std::string& name) const;

  //! Remove the given MachO::Symbol with the given name from the export table
  bool unexport(const std::string& name);

  //! Remove the given symbol from the export table
  bool unexport(const Symbol& sym);

  //! Return the MachO::Section that encompasses the provided offset.
  //! If a section can't be found, it returns a null pointer (``nullptr``)
  Section* section_from_offset(uint64_t offset);
  const Section* section_from_offset(uint64_t offset) const;

  //! Return the MachO::Section that encompasses the provided virtual address.
  //! If a section can't be found, it returns a null pointer (``nullptr``)
  Section* section_from_virtual_address(uint64_t virtual_address);
  const Section* section_from_virtual_address(uint64_t virtual_address) const;

  //! Convert a virtual address to an offset in the file
  result<uint64_t> virtual_address_to_offset(uint64_t virtual_address) const;

  //! Convert the given offset into a virtual address.
  //!
  //! @param[in] offset    The offset to convert.
  //! @param[in] slide     If not 0, it will replace the default base address (if any)
  result<uint64_t> offset_to_virtual_address(uint64_t offset, uint64_t slide = 0) const override;

  //! Return the binary's SegmentCommand that encompasses the provided offset
  //!
  //! If a SegmentCommand can't be found it returns a null pointer (``nullptr``).
  SegmentCommand* segment_from_offset(uint64_t offset);
  const SegmentCommand* segment_from_offset(uint64_t offset) const;

  //! Return the index of the given SegmentCommand
  size_t segment_index(const SegmentCommand& segment) const;

  //! Return binary's *fat offset*. ``0`` if not relevant.
  uint64_t fat_offset() const {
    return fat_offset_;
  }

  //! Return the binary's SegmentCommand which encompasses the given virtual address
  //! or a nullptr if not found.
  SegmentCommand* segment_from_virtual_address(uint64_t virtual_address);
  const SegmentCommand* segment_from_virtual_address(uint64_t virtual_address) const;

  //! Return the range of virtual addresses
  range_t va_ranges() const;

  //! Return the range of offsets
  range_t off_ranges() const;

  //! Check if the given address is encompassed in the
  //! binary's virtual addresses range
  bool is_valid_addr(uint64_t address) const;

  //! Method so that the ``visitor`` can visit us
  void accept(LIEF::Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  //! Patch the content at virtual address @p address with @p patch_value
  //!
  //! @param[in] address       Address to patch
  //! @param[in] patch_value   Patch to apply
  //! @param[in] addr_type     Specify if the address should be used as
  //!                          an absolute virtual address or an RVA
  void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value,
                     LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;

  //! Patch the address with the given value
  //!
  //! @param[in] address       Address to patch
  //! @param[in] patch_value   Patch to apply
  //! @param[in] size          Size of the value in **bytes** (1, 2, ... 8)
  //! @param[in] addr_type     Specify if the address should be used as
  //!                          an absolute virtual address or an RVA
  void patch_address(uint64_t address, uint64_t patch_value,
                     size_t size = sizeof(uint64_t),
                     LIEF::Binary::VA_TYPES addr_type = LIEF::Binary::VA_TYPES::AUTO) override;

  //! Return the content located at virtual address
  span<const uint8_t> get_content_from_virtual_address(
      uint64_t virtual_address, uint64_t size,
      Binary::VA_TYPES addr_type = Binary::VA_TYPES::AUTO) const override;

  //! The binary entrypoint
  uint64_t entrypoint() const override;

  //! Check if the binary is position independent
  bool is_pie() const override {
    return header().has(Header::FLAGS::PIE);
  }

  //! Check if the binary uses ``NX`` protection
  bool has_nx() const override {
    return !has_nx_stack();
  }

  /// Return True if the **heap** is flagged as non-executable. False otherwise
  bool has_nx_stack() const {
    return !header().has(Header::FLAGS::ALLOW_STACK_EXECUTION);
  }

  /// Return True if the **stack** is flagged as non-executable. False otherwise
  bool has_nx_heap() const {
    return !header().has(Header::FLAGS::NO_HEAP_EXECUTION);
  }

  //! ``true`` if the binary has an entrypoint.
  //!
  //! Basically for libraries it will return ``false``
  bool has_entrypoint() const {
    return has_main_command() || has_thread_command();
  }

  //! ``true`` if the binary has a MachO::UUIDCommand command.
  bool has_uuid() const;

  //! Return the MachO::UUIDCommand if present, a nullptr otherwise.
  UUIDCommand* uuid();
  const UUIDCommand* uuid() const;

  //! ``true`` if the binary has a MachO::MainCommand command.
  bool has_main_command() const;

  //! Return the MachO::MainCommand if present, a nullptr otherwise.
  MainCommand* main_command();
  const MainCommand* main_command() const;

  //! ``true`` if the binary has a MachO::DylinkerCommand.
  bool has_dylinker() const;

  //! Return the MachO::DylinkerCommand if present, a nullptr otherwise.
  DylinkerCommand* dylinker();
  const DylinkerCommand* dylinker() const;

  //! ``true`` if the binary has a MachO::DyldInfo command.
  bool has_dyld_info() const;

  //! Return the MachO::Dyld command if present, a nullptr otherwise.
  DyldInfo* dyld_info();
  const DyldInfo* dyld_info() const;

  //! ``true`` if the binary has a MachO::FunctionStarts command.
  bool has_function_starts() const;

  //! Return the MachO::FunctionStarts command if present, a nullptr otherwise.
  FunctionStarts* function_starts();
  const FunctionStarts* function_starts() const;

  //! ``true`` if the binary has a MachO::SourceVersion command.
  bool has_source_version() const;

  //! Return the MachO::SourceVersion command if present, a nullptr otherwise.
  SourceVersion* source_version();
  const SourceVersion* source_version() const;

  //! ``true`` if the binary has a MachO::VersionMin command.
  bool has_version_min() const;

  //! Return the MachO::VersionMin command if present, a nullptr otherwise.
  VersionMin* version_min();
  const VersionMin* version_min() const;

  //! ``true`` if the binary has a MachO::ThreadCommand command.
  bool has_thread_command() const;

  //! Return the MachO::ThreadCommand command if present, a nullptr otherwise.
  ThreadCommand* thread_command();
  const ThreadCommand* thread_command() const;

  //! ``true`` if the binary has a MachO::RPathCommand command.
  bool has_rpath() const;

  //! Return the MachO::RPathCommand command if present, a nullptr otherwise.
  RPathCommand* rpath();
  const RPathCommand* rpath() const;

  //! Iterator over **all** the MachO::RPathCommand commands.
  it_rpaths rpaths();
  it_const_rpaths rpaths() const;

  //! ``true`` if the binary has a MachO::SymbolCommand command.
  bool has_symbol_command() const;

  //! Return the MachO::SymbolCommand if present, a nullptr otherwise.
  SymbolCommand* symbol_command();
  const SymbolCommand* symbol_command() const;

  //! ``true`` if the binary has a MachO::DynamicSymbolCommand command.
  bool has_dynamic_symbol_command() const;

  //! Return the MachO::SymbolCommand if present, a nullptr otherwise.
  DynamicSymbolCommand* dynamic_symbol_command();
  const DynamicSymbolCommand* dynamic_symbol_command() const;

  //! ``true`` if the binary is signed with `LC_CODE_SIGNATURE` command
  bool has_code_signature() const;

  //! Return the MachO::CodeSignature if present, a nullptr otherwise.
  CodeSignature* code_signature();
  const CodeSignature* code_signature() const;

  //! ``true`` if the binary is signed with the command `DYLIB_CODE_SIGN_DRS`
  bool has_code_signature_dir() const;

  //! Return the MachO::CodeSignatureDir if present, a nullptr otherwise.
  CodeSignatureDir* code_signature_dir();
  const CodeSignatureDir* code_signature_dir() const;

  //! ``true`` if the binary has a MachO::DataInCode command.
  bool has_data_in_code() const;

  //! Return the MachO::DataInCode if present, a nullptr otherwise.
  DataInCode* data_in_code();
  const DataInCode* data_in_code() const;

  //! ``true`` if the binary has segment split info.
  bool has_segment_split_info() const;

  //! Return the MachO::SegmentSplitInfo if present, a nullptr otherwise.
  SegmentSplitInfo* segment_split_info();
  const SegmentSplitInfo* segment_split_info() const;

  //! ``true`` if the binary has a sub framework command.
  bool has_sub_framework() const;

  //! ``true`` if the binary has Encryption Info.
  bool has_encryption_info() const;

  //! Return the MachO::DyldEnvironment if present, a nullptr otherwise.
  EncryptionInfo* encryption_info();
  const EncryptionInfo* encryption_info() const;

  //! Return the MachO::SubFramework if present, a nullptr otherwise.
  SubFramework* sub_framework();
  const SubFramework* sub_framework() const;

  //! ``true`` if the binary has Dyld envrionment variables.
  bool has_dyld_environment() const;

  //! Return the MachO::DyldEnvironment if present, a nullptr otherwise
  DyldEnvironment* dyld_environment();
  const DyldEnvironment* dyld_environment() const;

  //! ``true`` if the binary has the BuildVersion command.
  bool has_build_version() const;

  //! Return the MachO::BuildVersion if present, a nullptr otherwise.
  BuildVersion* build_version();
  const BuildVersion* build_version() const;

  //! ``true`` if the binary has the command LC_DYLD_CHAINED_FIXUPS.
  bool has_dyld_chained_fixups() const;

  //! Return the MachO::DyldChainedFixups if present, a nullptr otherwise.
  DyldChainedFixups* dyld_chained_fixups();
  const DyldChainedFixups* dyld_chained_fixups() const;

  //! ``true`` if the binary has the command LC_DYLD_CHAINED_FIXUPS.
  bool has_dyld_exports_trie() const;

  //! Return the MachO::DyldChainedFixups if present, a nullptr otherwise.
  DyldExportsTrie* dyld_exports_trie();
  const DyldExportsTrie* dyld_exports_trie() const;

  //! ``true`` if the binary has the command LC_TWO_LEVEL_HINTS.
  bool has_two_level_hints() const;

  //! Return the MachO::DyldChainedFixups if present, a nullptr otherwise.
  TwoLevelHints* two_level_hints();
  const TwoLevelHints* two_level_hints() const;

  //! ``true`` if the binary has the command LC_LINKER_OPTIMIZATION_HINT.
  bool has_linker_opt_hint() const;

  //! Return the MachO::LinkerOptHint if present, a nullptr otherwise.
  LinkerOptHint* linker_opt_hint();
  const LinkerOptHint* linker_opt_hint() const;

  //! Add a symbol in the export trie of the current binary
  ExportInfo* add_exported_function(uint64_t address, const std::string& name);

  //! Add a symbol in LC_SYMTAB command of the current binary
  Symbol* add_local_symbol(uint64_t address, const std::string& name);

  //! Return Objective-C metadata if present
  std::unique_ptr<objc::Metadata> objc_metadata() const;

  template<class T>
  LIEF_LOCAL bool has_command() const;

  template<class T>
  LIEF_LOCAL T* command();

  template<class T>
  LIEF_LOCAL const T* command() const;

  template<class T>
  LIEF_LOCAL size_t count_commands() const;

  template<class CMD, class Func>
  LIEF_LOCAL Binary& for_commands(Func f);

  LoadCommand* operator[](LoadCommand::TYPE type) {
    return get(type);
  }
  const LoadCommand* operator[](LoadCommand::TYPE type) const {
    return get(type);
  }

  //! Return the list of the MachO's constructors
  LIEF::Binary::functions_t ctor_functions() const override;

  //! Return all the functions found in this MachO
  LIEF::Binary::functions_t functions() const;

  //! Return the functions found in the ``__unwind_info`` section
  LIEF::Binary::functions_t unwind_functions() const;

  //! ``true`` if the binary has a LoadCommand::TYPE::FILESET_ENTRY command
  bool has_filesets() const;

  //! Name associated with the LC_FILESET_ENTRY binary
  const std::string& fileset_name() const {
    return fileset_name_;
  }

  ~Binary() override;

  //! Shift the content located right after the Load commands table.
  //! This operation can be used to add a new command
  ok_error_t shift(size_t value);

  //! Shift the position on the __LINKEDIT data by `width`
  ok_error_t shift_linkedit(size_t width);

  //! If this Mach-O binary has been parsed from memory,
  //! it returns the in-memory base address of this binary.
  //!
  //! Otherwise, it returns 0
  uint64_t memory_base_address() const {
    return in_memory_base_addr_;
  }

  // Check if the binary is supporting ARM64 pointer authentication (arm64e)
  bool support_arm64_ptr_auth() const {
    static constexpr auto CPU_SUBTYPE_ARM64E = 2;
    return header().cpu_type() == Header::CPU_TYPE::ARM64 &&
           (header().cpu_subtype() & ~Header::CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
  }

  uint32_t page_size() const;

  static bool classof(const LIEF::Binary* bin) {
    return bin->format() == Binary::FORMATS::MACHO;
  }

  span<const uint8_t> overlay() const {
    return overlay_;
  }

  private:
  //! Default constructor
  Binary();

  void shift_command(size_t width, uint64_t from_offset);

  //! Insert a Segment command in the cache field (segments_)
  //! and keep a consistent state of the indexes.
  size_t add_cached_segment(SegmentCommand& segment);
  void refresh_seg_offset();

  template<class T>
  LIEF_LOCAL ok_error_t patch_relocation(Relocation& relocation, uint64_t from, uint64_t shift);

  LIEF::Header              get_abstract_header() const override;
  LIEF::Binary::sections_t          get_abstract_sections() override;
  LIEF::Binary::symbols_t           get_abstract_symbols() override;
  LIEF::Binary::relocations_t       get_abstract_relocations() override;
  LIEF::Binary::functions_t get_abstract_exported_functions() const override;
  LIEF::Binary::functions_t get_abstract_imported_functions() const override;
  std::vector<std::string>  get_abstract_imported_libraries() const override;

  relocations_t& relocations_list() {
    return this->relocations_;
  }

  const relocations_t& relocations_list() const {
    return this->relocations_;
  }

  size_t pointer_size() const {
    return this->is64_ ? sizeof(uint64_t) : sizeof(uint32_t);
  }

  bool        is64_ = true;
  Header      header_;
  commands_t  commands_;
  symbols_t   symbols_;

  // Same purpose as sections_cache_t
  libraries_cache_t libraries_;

  // The sections are owned by the SegmentCommand object.
  // This attribute is a cache to speed-up the iteration
  sections_cache_t sections_;

  // Same purpose as sections_cache_t
  segments_cache_t segments_;

  fileset_binaries_t filesets_;

  // Cached relocations from segment / sections
  mutable relocations_t relocations_;
  int32_t available_command_space_ = 0;

  // This is used to improve performances of
  // offset_to_virtual_address
  std::map<uint64_t, SegmentCommand*> offset_seg_;

  protected:
  uint64_t fat_offset_ = 0;
  uint64_t fileset_offset_ = 0;
  uint64_t in_memory_base_addr_ = 0;
  std::string fileset_name_;
  std::vector<uint8_t> overlay_;
};

} // namespace MachO
} // namespace LIEF
#endif
