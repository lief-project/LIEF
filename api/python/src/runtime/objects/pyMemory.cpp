#include <sstream>
#include "LIEF/runtime/Memory.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/stl/optional.h>
#include <nanobind/extra/memoryview.hpp>

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::runtime::py {
template<>
void create<Memory>(nb::module_& m) {
  nb::class_<Memory> obj(m, "Memory",
    R"doc(
    This class exposes API to access and manage memory
    )doc"_doc
  );

  nb::enum_<Memory::MMAP_FLAGS>(obj, "MMAP_FLAGS", nb::is_arithmetic(), nb::is_flag(),
    "Flags used when creating a memory map (mmap)."_doc
  )
    .value("NONE", Memory::MMAP_FLAGS::MP_NONE)
    .value("PRIVATE", Memory::MMAP_FLAGS::MP_PRIVATE,
           "Changes are private to this process (copy-on-write)."_doc)
    .value("ANONYMOUS", Memory::MMAP_FLAGS::MP_ANONYMOUS,
           "The mapping is not backed by any file."_doc)
    .value("SHARED", Memory::MMAP_FLAGS::MP_SHARED,
           "Changes are shared."_doc)
    .value("FIXED", Memory::MMAP_FLAGS::MP_FIXED,
           "Interpret the address as a fixed requirement."_doc)
    .value("JIT", Memory::MMAP_FLAGS::MP_JIT,
           "Map for Just-In-Time code generation."_doc).export_values();

  nb::enum_<Memory::PERM>(obj, "PERM", nb::is_arithmetic(), nb::is_flag())
    .value("NONE", Memory::PERM::P_NONE)
    .value("READ", Memory::PERM::P_READ)
    .value("WRITE", Memory::PERM::P_WRITE)
    .value("EXEC", Memory::PERM::P_EXEC).export_values();


  using Chunk = Memory::Chunk;
  nb::class_<Chunk>(obj, "Chunk",
    R"doc(
    Represents a contiguous chunk of memory allocated or inspected by the runtime.
    )doc"_doc
  )
    .def(nb::init<void*, size_t, uint32_t>(),
         "addr"_a, "size"_a, "permissions"_a)
    .def(nb::init<void*, size_t>(), "addr"_a, "size"_a)
    .def(nb::init<void*>(), "addr"_a)
    .def_prop_ro("addr_ptr", nb::overload_cast<>(&Chunk::addr_ptr),
      "Returns the start address of the memory chunk as an opaque pointer"_doc
    )
    .def_prop_ro("addr", nb::overload_cast<>(&Chunk::addr, nb::const_),
      "Returns the start address of the memory chunk"_doc
    )
    .def_prop_ro("size", &Chunk::size,
      "Returns the size of the memory chunk in bytes."_doc
    )
    .def_prop_ro("permissions", &Chunk::permissions,
      "Returns the current permissions of the memory chunk."_doc
    )
    .def_prop_ro("page_start", &Chunk::page_start,
      "Returns the address of the start of the page containing this chunk."_doc
    )
    .def_prop_ro("page_end", &Chunk::page_end,
      "Returns the address of the end of the page containing this chunk."_doc
    )
    .def("change_permissions", &Chunk::change_permissions,
      "Changes the permissions of the memory chunk."_doc,
      "permission"_a, nb::rv_policy::reference_internal
    )
    .def("make_x", &Chunk::make_x,
      "Sets the permissions to Execute only."_doc,
      nb::rv_policy::reference_internal
    )
    .def("make_rw", &Chunk::make_rw,
      "Sets the permissions to Read and Write."_doc,
      nb::rv_policy::reference_internal
    )
    .def("make_rx", &Chunk::make_rx,
      "Sets the permissions to Read and Execute."_doc,
      nb::rv_policy::reference_internal
    )
    .def("make_rwx", &Chunk::make_rwx,
      "Sets the permissions to read/write/exec"_doc,
      nb::rv_policy::reference_internal
    )
    .def("make_ro", &Chunk::make_ro,
      "Sets the permissions to Read Only."_doc,
      nb::rv_policy::reference_internal
    )
    .def("cache_flush", &Chunk::cache_flush,
      R"doc(
      Flushes the instruction cache for this memory chunk.
      This should be used when modifying code in memory (e.g., hooking, JIT).
      )doc"_doc,
      nb::rv_policy::reference_internal
    )
    .def("is_valid", &Chunk::is_valid)
    .def("__bool__", &Chunk::is_valid)

    .def("deallocate", &Chunk::deallocate)

    LIEF_DEFAULT_STR(Chunk);

  obj
    .def_static("mmap", &Memory::mmap,
      "Allocates a memory chunk through mmap-like function"_doc,
      "size"_a, "flags"_a, "permissions"_a = Memory::P_NONE)

    .def_static("munmap", &Memory::munmap,
      "Deallocates a mmaped memory chunk"_doc,
      "chunk"_a)

    .def_static("mprotect", &Memory::mprotect,
      "Sets the permission of the given memory chunk"_doc,
      "chunk"_a, "flags"_a)

    .def_static("perm_str", &Memory::perm_str,
        "Convert the given permission into a human-readable string"_doc,
        "flags"_a
      )

    .def_static("write", [] (const void* ptr, size_t size, uintptr_t addr) {
        return Memory::write(reinterpret_cast<const uint8_t*>(ptr), size, addr);
    }, "ptr"_a, "size"_a, "addr"_a)

    .def_static("write", [] (nb::extra::memoryview buffer, uintptr_t addr) {
      return Memory::write(buffer.data(), buffer.size(), addr);
    }, "buffer"_a, "addr"_a)

    .def_static("write", [] (nb::bytes buffer, uintptr_t addr) {
      return Memory::write(reinterpret_cast<const uint8_t*>(buffer.data()),
                           buffer.size(), addr);
    }, "buffer"_a, "addr"_a)

    .def_static("write_u8", &Memory::write<uint8_t>, "value"_a, "addr"_a)
    .def_static("write_i8", &Memory::write<int8_t>, "value"_a, "addr"_a)

    .def_static("write_u16", &Memory::write<uint16_t>, "value"_a, "addr"_a)
    .def_static("write_i16", &Memory::write<int16_t>, "value"_a, "addr"_a)

    .def_static("write_u32", &Memory::write<uint32_t>, "value"_a, "addr"_a)
    .def_static("write_i32", &Memory::write<int32_t>, "value"_a, "addr"_a)

    .def_static("write_u64", &Memory::write<uint64_t>, "value"_a, "addr"_a)
    .def_static("write_i64", &Memory::write<int64_t>, "value"_a, "addr"_a)

    .def_static("read", [] (uintptr_t addr, size_t size) {
      std::vector<uint8_t> buffer;
      Memory::read(addr, buffer, size);
      return nb::bytes(buffer.data(), buffer.size());
    }, "addr"_a, "size"_a)

    .def_static("read", [] (uintptr_t addr, void* out, size_t size) {
      Memory::read(addr, reinterpret_cast<uint8_t*>(out), size);
    }, "addr"_a, "out"_a, "size"_a)

    .def_static("read_u8", &Memory::read<uint8_t>, "addr"_a)
    .def_static("read_i8", &Memory::read<int8_t>, "addr"_a)

    .def_static("read_u16", &Memory::read<uint16_t>, "addr"_a)
    .def_static("read_i16", &Memory::read<int16_t>, "addr"_a)

    .def_static("read_u32", &Memory::read<uint32_t>, "addr"_a)
    .def_static("read_i32", &Memory::read<int32_t>, "addr"_a)

    .def_static("read_u64", &Memory::read<uint64_t>, "addr"_a)
    .def_static("read_i64", &Memory::read<int64_t>, "addr"_a);
}

}
