#include "LIEF/runtime/windows/LdrDataTableEntry.hpp"
#include "LIEF/runtime/windows/PEB.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>

#include "pyOwningIterator.hpp"

namespace LIEF::runtime::windows::py {

template<>
void create<PEB>(nb::module_& m) {
  nb::class_<PEB>(
      m, "PEB",
      R"doc(
      This class exposes a user-friendly interface over the Process Environment
      Block (PEB) of the current process.

      It can be accessed through :attr:`lief.runtime.windows.Process.peb`.
      )doc"_doc
  )
      .def_prop_ro("being_debugged", &PEB::being_debugged,
                   "Whether the current process is being debugged."_doc)

      .def_prop_ro(
          "ldr", &PEB::ldr,
          R"doc(
          Address of the loader data structure (``PEB_LDR_DATA``) which holds the
          list of the modules loaded in the current process.
          )doc"_doc
      )

      .def_prop_ro(
          "process_parameters", &PEB::process_parameters,
          R"doc(
          Address of the process parameters (``RTL_USER_PROCESS_PARAMETERS``) which
          holds information such as the command line or the current directory.
          )doc"_doc
      )

      .def_prop_ro(
          "atl_thunk_slist_ptr", &PEB::atl_thunk_slist_ptr,
          "Address of the per-process ATL thunk SList (single-linked list)."_doc
      )

      .def_prop_ro("atl_thunk_slist_ptr32", &PEB::atl_thunk_slist_ptr32,
                   "32-bit value of the ATL thunk SList pointer."_doc)

      .def_prop_ro("post_process_init_routine", &PEB::post_process_init_routine,
                   R"doc(
                   Address of the routine called once the process completed its
                   initialization (``PostProcessInitRoutine``).
                   )doc"_doc)

      .def_prop_ro("session_id", &PEB::session_id,
                   "Session ID associated with the current process."_doc)

      .def_prop_ro(
          "entries",
          [](const PEB& self) {
            auto entries = LIEF::py::owning_range(self.entries());
            return nb::make_iterator<nb::rv_policy::take_ownership>(
                nb::type<LdrDataTableEntry>(), "ldr_entries_iterator", entries
            );
          },
          R"doc(
          Iterate over the modules referenced by the loader data of the PEB, in load
          order, yielding :class:`~lief.runtime.windows.LdrDataTableEntry` objects.
          )doc"_doc
      );
}

}
