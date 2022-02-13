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
#ifndef LIEF_MACHO_DYLD_INFO_COMMAND_H_
#define LIEF_MACHO_DYLD_INFO_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/span.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/type_traits.hpp"
#include "LIEF/iterators.hpp"

namespace LIEF {
class BinaryStream;
namespace MachO {

class Builder;
class BinaryParser;
class SegmentCommand;
class BindingInfo;
class ExportInfo;

namespace details {
struct dyld_info_command;
}

//! Class that represents the LC_DYLD_INFO and LC_DYLD_INFO_ONLY commands
class LIEF_API DyldInfo : public LoadCommand {

  friend class BinaryParser;
  friend class Binary;
  friend class Builder;
  friend class SegmentCommand;

  public:
  //! Tuple of ``offset`` and ``size``
  using info_t = std::pair<uint32_t, uint32_t>;

  //! Internal container for storing BindingInfo
  using binding_info_t = std::vector<std::unique_ptr<BindingInfo>>;

  //! Iterator which outputs BindingInfo&
  using it_binding_info = ref_iterator<binding_info_t&, BindingInfo*>;

  //! Iterator which outputs const BindingInfo&
  using it_const_binding_info = const_ref_iterator<const binding_info_t&, BindingInfo*>;

  //! Internal container for storing ExportInfo
  using export_info_t = std::vector<std::unique_ptr<ExportInfo>>;

  //! Iterator which outputs const BindingInfo&
  using it_export_info = ref_iterator<export_info_t&, ExportInfo*>;

  //! Iterator which outputs const ExportInfo&
  using it_const_export_info = const_ref_iterator<const export_info_t&, ExportInfo*>;


  enum class BINDING_ENCODING_VERSION {
    UNKNOWN = 0,
    V1,
    V2
  };

  DyldInfo();
  DyldInfo(const details::dyld_info_command& dyld_info_cmd);

  DyldInfo& operator=(DyldInfo other);
  DyldInfo(const DyldInfo& copy);

  void swap(DyldInfo& other);

  DyldInfo* clone() const override;

  virtual ~DyldInfo();

  //! *Rebase* information
  //!
  //! Dyld rebases an image whenever dyld loads it at an address different
  //! from its preferred address.  The rebase information is a stream
  //! of byte sized opcodes for which symbolic names start with REBASE_OPCODE_.
  //! Conceptually the rebase information is a table of tuples:
  //!    <seg-index, seg-offset, type>
  //! The opcodes are a compressed way to encode the table by only
  //! encoding when a column changes.  In addition simple patterns
  //! like "every n'th offset for m times" can be encoded in a few
  //! bytes.
  //!
  //! @see ``/usr/include/mach-o/loader.h``
  const info_t& rebase() const;

  //! Return Rebase's opcodes as raw data
  span<const uint8_t> rebase_opcodes() const;
  span<uint8_t>       rebase_opcodes();

  //! Set new opcodes
  void rebase_opcodes(buffer_t raw);


  //! Return the rebase opcodes in a humman-readable way
  std::string show_rebases_opcodes() const;

  //! *Bind* information
  //!
  //! Dyld binds an image during the loading process, if the image
  //! requires any pointers to be initialized to symbols in other images.
  //! The rebase information is a stream of byte sized
  //! opcodes for which symbolic names start with BIND_OPCODE_.
  //! Conceptually the bind information is a table of tuples:
  //!    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
  //! The opcodes are a compressed way to encode the table by only
  //! encoding when a column changes.  In addition simple patterns
  //! like for runs of pointers initialzed to the same value can be
  //! encoded in a few bytes.
  //!
  //! @see ``/usr/include/mach-o/loader.h``
  const info_t& bind() const;

  //! Return Binding's opcodes as raw data
  span<const uint8_t> bind_opcodes() const;
  span<uint8_t>       bind_opcodes();

  //! Set new opcodes
  void bind_opcodes(buffer_t raw);

  //! Return the bind opcodes in a humman-readable way
  std::string show_bind_opcodes() const;

  //! *Weak Bind* information
  //!
  //! Some C++ programs require dyld to unique symbols so that all
  //! images in the process use the same copy of some code/data.
  //! This step is done after binding. The content of the weak_bind
  //! info is an opcode stream like the bind_info.  But it is sorted
  //! alphabetically by symbol name.  This enables dyld to walk
  //! all images with weak binding information in order and look
  //! for collisions.  If there are no collisions, dyld does
  //! no updating.  That means that some fixups are also encoded
  //! in the bind_info.  For instance, all calls to "operator new"
  //! are first bound to libstdc++.dylib using the information
  //! in bind_info.  Then if some image overrides operator new
  //! that is detected when the weak_bind information is processed
  //! and the call to operator new is then rebound.
  //!
  //! @see ``/usr/include/mach-o/loader.h``
  const info_t& weak_bind() const;

  //! Return **Weak** Binding's opcodes as raw data
  span<const uint8_t> weak_bind_opcodes() const;
  span<uint8_t>       weak_bind_opcodes();

  //! Set new opcodes
  void weak_bind_opcodes(buffer_t raw);

  //! Return the bind opcodes in a humman-readable way
  std::string show_weak_bind_opcodes() const;

  //! *Lazy Bind* information
  //!
  //! Some uses of external symbols do not need to be bound immediately.
  //! Instead they can be lazily bound on first use.  The lazy_bind
  //! are contains a stream of BIND opcodes to bind all lazy symbols.
  //! Normal use is that dyld ignores the lazy_bind section when
  //! loading an image.  Instead the static linker arranged for the
  //! lazy pointer to initially point to a helper function which
  //! pushes the offset into the lazy_bind area for the symbol
  //! needing to be bound, then jumps to dyld which simply adds
  //! the offset to lazy_bind_off to get the information on what
  //! to bind.
  //!
  //! @see ``/usr/include/mach-o/loader.h``
  const info_t& lazy_bind() const;

  //! Return **Lazy** Binding's opcodes as raw data
  span<const uint8_t> lazy_bind_opcodes() const;
  span<uint8_t>       lazy_bind_opcodes();

  //! Set new opcodes
  void lazy_bind_opcodes(buffer_t raw);

  //! Return the lazy opcodes in a humman-readable way
  std::string show_lazy_bind_opcodes() const;

  //! Iterator over BindingInfo entries
  it_binding_info       bindings();
  it_const_binding_info bindings() const;

  //! *Export* information
  //!
  //! The symbols exported by a dylib are encoded in a trie.  This
  //! is a compact representation that factors out common prefixes.
  //! It also reduces LINKEDIT pages in RAM because it encodes all
  //! information (name, address, flags) in one small, contiguous range.
  //! The export area is a stream of nodes.  The first node sequentially
  //! is the start node for the trie.
  //!
  //! Nodes for a symbol start with a byte that is the length of
  //! the exported symbol information for the string so far.
  //! If there is no exported symbol, the byte is zero. If there
  //! is exported info, it follows the length byte.  The exported
  //! info normally consists of a flags and offset both encoded
  //! in uleb128.  The offset is location of the content named
  //! by the symbol.  It is the offset from the mach_header for
  //! the image.
  //!
  //! After the initial byte and optional exported symbol information
  //! is a byte of how many edges (0-255) that this node has leaving
  //! it, followed by each edge.
  //! Each edge is a zero terminated cstring of the addition chars
  //! in the symbol, followed by a uleb128 offset for the node that
  //! edge points to.
  //!
  //! @see ``/usr/include/mach-o/loader.h``
  const info_t& export_info() const;

  //! Iterator over ExportInfo entries
  it_export_info       exports();
  it_const_export_info exports() const;

  //! Return Export's trie as raw data
  span<const uint8_t> export_trie() const;
  span<uint8_t>       export_trie();

  //! Set new trie
  void export_trie(buffer_t raw);

  //! Return the export trie in a humman-readable way
  std::string show_export_trie() const;

  void rebase(const info_t& info);
  void bind(const info_t& info);
  void weak_bind(const info_t& info);
  void lazy_bind(const info_t& info);
  void export_info(const info_t& info);

  void set_rebase_offset(uint32_t offset);
  void set_rebase_size(uint32_t size);

  void set_bind_offset(uint32_t offset);
  void set_bind_size(uint32_t size);

  void set_weak_bind_offset(uint32_t offset);
  void set_weak_bind_size(uint32_t size);

  void set_lazy_bind_offset(uint32_t offset);
  void set_lazy_bind_size(uint32_t size);

  void set_export_offset(uint32_t offset);
  void set_export_size(uint32_t size);

  bool operator==(const DyldInfo& rhs) const;
  bool operator!=(const DyldInfo& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  using bind_container_t = std::set<BindingInfo*, std::function<bool(BindingInfo*, BindingInfo*)>>;

  void show_bindings(std::ostream& os, span<const uint8_t> buffer, bool is_lazy = false) const;

  void show_trie(std::ostream& output, std::string output_prefix, BinaryStream& stream, uint64_t start, uint64_t end, const std::string& prefix) const;

  LIEF_LOCAL DyldInfo& update_standard_bindings(const bind_container_t& bindings);
  LIEF_LOCAL DyldInfo& update_standard_bindings_v1(const bind_container_t& bindings);
  LIEF_LOCAL DyldInfo& update_standard_bindings_v2(const bind_container_t& bindings, std::vector<RelocationDyld*> rebases);

  LIEF_LOCAL DyldInfo& update_weak_bindings(const bind_container_t& bindings);
  LIEF_LOCAL DyldInfo& update_lazy_bindings(const bind_container_t& bindings);

  LIEF_LOCAL DyldInfo& update_rebase_info();
  LIEF_LOCAL DyldInfo& update_binding_info();
  LIEF_LOCAL DyldInfo& update_export_trie();

  info_t   rebase_;
  span<uint8_t> rebase_opcodes_;

  info_t   bind_;
  span<uint8_t> bind_opcodes_;

  info_t   weak_bind_;
  span<uint8_t> weak_bind_opcodes_;

  info_t   lazy_bind_;
  span<uint8_t> lazy_bind_opcodes_;

  info_t   export_;
  span<uint8_t> export_trie_;

  export_info_t  export_info_;
  binding_info_t binding_info_;

  BINDING_ENCODING_VERSION binding_encoding_version_ = BINDING_ENCODING_VERSION::UNKNOWN;

  Binary* binary_ = nullptr;
};

}
}
#endif
