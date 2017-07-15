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
#ifndef LIEF_MACHO_BINARY_H_
#define LIEF_MACHO_BINARY_H_

#include <vector>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/MachO/type_traits.hpp"
#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/Header.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/DylinkerCommand.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/MainCommand.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/SourceVersion.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class Builder;

//! @brief Class which represent a MachO binary
class DLL_PUBLIC Binary : public LIEF::Binary  {

  friend class BinaryParser;
  friend class Builder;

  public:
    Binary(const Binary&) = delete;

    //! @brief Return a reference to MachO::Header
    Header&       header(void);
    const Header& header(void) const;

    //! @brief Return binary's @link MachO::LoadCommand load commands @endlink
    it_commands       commands(void);
    it_const_commands commands(void) const;

    //! @brief Return binary's @link MachO::Symbol symbols @endlink
    it_symbols       symbols(void);
    it_const_symbols symbols(void) const;

    static bool                 is_exported(const Symbol& symbol);

    //! @brief Return binary's exported symbols
    it_exported_symbols       get_exported_symbols(void);
    it_const_exported_symbols get_exported_symbols(void) const;

    //! @brief Check if the given symbol is a imported one
    static bool is_imported(const Symbol& symbol);

    //! @brief Return binary's imported symbols
    it_imported_symbols       get_imported_symbols(void);
    it_const_imported_symbols get_imported_symbols(void) const;

    //! @brief Return binary imported libraries (MachO::DylibCommand)
    it_libraries       libraries(void);
    it_const_libraries libraries(void) const;

    //! @brief Return binary's @link MachO::SegmentCommand segments @endlink
    it_segments       segments(void);
    it_const_segments segments(void) const;

    //! @brief Return binary's @link MachO::Section sections @endlink
    it_sections       sections(void);
    it_const_sections sections(void) const;

    //! @brief Reconstruct the binary object and write it in `filename`
    //! @param filename Path to write the reconstructed binary
    void write(const std::string& filename);

    //! @brief Reconstruct the binary object and return his content as bytes
    std::vector<uint8_t> raw(void);

    //! @brief insert load_command
    LoadCommand& insert_command(const LoadCommand& command);

    //! @brief Remove ``PIE`` flag
    bool disable_pie(void);

    //! @brief Return binary's imagebase
    uint64_t imagebase(void) const;

    //! @brief Return binary's loader (e.g. ``/usr/lib/dyld``)
    const std::string& get_loader(void) const;

    // ======
    // Helper
    // ======

    //! @brief Return binary's @link MachO::Section section @endlink
    //! which holds the offset
    Section&       section_from_offset(uint64_t offset);
    const Section& section_from_offset(uint64_t offset) const;

    //! @brief Convert a virtual address to an offset in the file
    uint64_t virtual_address_to_offset(uint64_t virtualAddress) const;


    // @brief Return binary's @link MachO::SegmentCommand segment command
    // which hold the offset
    SegmentCommand&       segment_from_offset(uint64_t offset);
    const SegmentCommand& segment_from_offset(uint64_t offset) const;

    uint64_t fat_offset() const { return fat_offset_; }

    // @brief Return binary's @link MachO::SegmentCommand segment command
    // which hold the virtual address
    SegmentCommand&       segment_from_virtual_address(uint64_t virtual_address);
    const SegmentCommand& segment_from_virtual_address(uint64_t virtual_address) const;

    //! @brief Method so that the ``visitor`` can visit us
    virtual void accept(LIEF::Visitor& visitor) const override;

    virtual ~Binary(void);

    virtual std::ostream& print(std::ostream& os) const override;

    // LIEF Interface
    // ==============

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

    //! @brief Return the content located at virtual address
    virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const override;

    virtual uint64_t entrypoint(void) const override;

    //! @brief ``true`` if the binary has an entrypoint.
    //!
    //! Basically for libraries it will return ``false``
    bool has_entrypoint(void) const;

    //! @brief ``true`` if the binary has an MachO::UUIDCommand command.
    bool has_uuid(void) const;

    //! @brief Return the MachO::UUIDCommand
    UUIDCommand&       uuid(void);
    const UUIDCommand& uuid(void) const;

    //! @brief ``true`` if the binary has a MachO::MainCommand command.
    bool has_main_command(void) const;

    //! @brief Return the MachO::MainCommand
    MainCommand&       main_command(void);
    const MainCommand& main_command(void) const;

    //! @brief ``true`` if the binary has a MachO::DylinkerCommand.
    bool has_dylinker(void) const;

    //! @brief Return the MachO::DylinkerCommand
    DylinkerCommand&       dylinker(void);
    const DylinkerCommand& dylinker(void) const;

    //! @brief ``true`` if the binary has a MachO::DyldInfo command.
    bool has_dyld_info(void) const;

    //! @brief Return the MachO::Dyld command
    DyldInfo&       dyld_info(void);
    const DyldInfo& dyld_info(void) const;

    //! @brief ``true`` if the binary has a MachO::FunctionStarts command.
    bool has_function_starts(void) const;

    //! @brief Return the MachO::FunctionStarts command
    FunctionStarts&       function_starts(void);
    const FunctionStarts& function_starts(void) const;

    //! @brief ``true`` if the binary has a MachO::SourceVersion command.
    bool has_source_version(void) const;

    //! @brief Return the MachO::SourceVersion command
    SourceVersion&       source_version(void);
    const SourceVersion& source_version(void) const;

    template<class T>
    bool has_command(void) const;

    template<class T>
    T& get_command(void);

    template<class T>
    const T& get_command(void) const;

    template<class T>
    size_t count_commands(void) const;


  private:
    //! @brief Default constructor
    Binary(void);

    virtual LIEF::Header              get_abstract_header(void) const override;
    virtual LIEF::sections_t          get_abstract_sections(void) override;
    virtual LIEF::symbols_t           get_abstract_symbols(void) override;
    virtual std::vector<std::string>  get_abstract_exported_functions(void) const override;
    virtual std::vector<std::string>  get_abstract_imported_functions(void) const override;
    virtual std::vector<std::string>  get_abstract_imported_libraries(void) const override;

    bool       is64_;
    Header     header_;
    commands_t commands_;
    symbols_t  symbols_;

  protected:
    uint64_t fat_offset_ = 0;
};

} // namespace MachO
} // namespace LIEF
#endif
