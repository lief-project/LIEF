#include <sstream>

#include "LIEF/runtime/windows/LdrDataTableEntry.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"
#include <nanobind/stl/optional.h>

namespace LIEF::runtime::windows::py {

template<>
void create<LdrDataTableEntry>(nb::module_& m) {
  nb::class_<LdrDataTableEntry>(m, "LdrDataTableEntry",
    R"doc(
    This class exposes a user-friendly interface over a ``LDR_DATA_TABLE_ENTRY``,
    the structure used by the Windows loader to describe a module loaded in the
    current process.

    These entries can be enumerated through :meth:`lief.runtime.windows.PEB.entries`.
    )doc"_doc
  )
    .def_prop_ro("dll_base", &LdrDataTableEntry::dll_base,
      "Base address at which the module is mapped in memory (``DllBase``)."_doc)

    .def_prop_ro("entry_point", &LdrDataTableEntry::entry_point,
      "Address of the entry point of the module (``EntryPoint``)."_doc)

    .def_prop_ro("size_of_image", &LdrDataTableEntry::size_of_image,
      "Size (in bytes) of the module's image in memory (``SizeOfImage``)."_doc)

    .def_prop_ro("full_dll_name", &LdrDataTableEntry::full_dll_name,
      R"doc(
      Full path of the module (``FullDllName``),
      e.g. ``C:\Windows\System32\ntdll.dll``.
      )doc"_doc)

    .def_prop_ro("base_dll_name", &LdrDataTableEntry::base_dll_name,
      "Base name of the module (``BaseDllName``), e.g. ``ntdll.dll``."_doc)

    .def_prop_ro("flags", &LdrDataTableEntry::flags,
      "Loader flags describing the state of the module (``Flags``)."_doc)

    .def_prop_ro("obsolete_load_count", &LdrDataTableEntry::obsolete_load_count,
      R"doc(
      Legacy load count of the module (``ObsoleteLoadCount``). Superseded by
      :attr:`~.reference_count` on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("tls_index", &LdrDataTableEntry::tls_index,
      "TLS slot index assigned to the module, or ``0`` when it has no TLS "
      "(``TlsIndex``)."_doc)

    .def_prop_ro("time_date_stamp", &LdrDataTableEntry::time_date_stamp,
      "``TimeDateStamp`` of the module as cached by the loader."_doc)

    .def_prop_ro("entry_point_activation_context",
      &LdrDataTableEntry::entry_point_activation_context,
      R"doc(
      Address of the activation context associated with the module's entry
      point.
      )doc"_doc)

    .def_prop_ro("lock", &LdrDataTableEntry::lock,
      "Address of the per-entry loader lock."_doc)

    .def_prop_ro("ddag_node", &LdrDataTableEntry::ddag_node,
      R"doc(
      Address of the dependency-graph node of the module (``DdagNode``).

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("load_context", &LdrDataTableEntry::load_context,
      R"doc(
      Address of the loader context used while the module is being snapped

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("parent_dll_base", &LdrDataTableEntry::parent_dll_base,
      R"doc(
      Base address of the module that triggered the load of this one.

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("switch_back_context", &LdrDataTableEntry::switch_back_context,
      R"doc(
      Address of the CHPE switch-back context.

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("original_base", &LdrDataTableEntry::original_base,
      R"doc(
      Preferred base address recorded in the PE headers

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("load_time", &LdrDataTableEntry::load_time,
      R"doc(
      Time at which the module was loaded.

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("base_name_hash_value",
      &LdrDataTableEntry::base_name_hash_value,
      R"doc(
      Hash of the module's base name used to index the loader tables

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("load_reason", &LdrDataTableEntry::load_reason,
      R"doc(
      Reason why the module was loaded, as a ``LDR_DLL_LOAD_REASON`` value

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("implicit_path_options",
      &LdrDataTableEntry::implicit_path_options,
      R"doc(
      Path-search options implied when the module was resolved

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("reference_count", &LdrDataTableEntry::reference_count,
      R"doc(
      Number of references currently held on the module.

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("dependent_load_flags",
      &LdrDataTableEntry::dependent_load_flags,
      R"doc(
      Flags controlling how the statically-linked dependencies of the module
      are loaded.

      .. note::

         Available on Windows 8 and later.
      )doc"_doc)

    .def_prop_ro("signing_level", &LdrDataTableEntry::signing_level,
      R"doc(
      Signing level of the module's image, as a ``SE_SIGNING_LEVEL`` value

      .. note::

         Available on Windows 10 and later.
      )doc"_doc)

    .def_prop_ro("check_sum", &LdrDataTableEntry::check_sum,
      R"doc(
      Image checksum cached by the loader

      .. note::

         Available on Windows 10 and later.
      )doc"_doc)

    .def_prop_ro("active_patch_image_base",
      &LdrDataTableEntry::active_patch_image_base,
      R"doc(
      Base address of the active hot-patch image, if any.

      .. note::

         Available on Windows 11 and later.
      )doc"_doc)

    .def_prop_ro("hot_patch_state", &LdrDataTableEntry::hot_patch_state,
      R"doc(
      State of the hot-patch engine for this module, as a
      ``LDR_HOT_PATCH_STATE`` value.

      .. note::

         Available on Windows 11 and later.
      )doc"_doc)

    LIEF_DEFAULT_STR(LdrDataTableEntry)
  ;
}

}
