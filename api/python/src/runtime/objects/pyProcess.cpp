#include "LIEF/runtime/Process.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"
#include "nanobind/stl/unordered_map.h"
#include <nanobind/stl/optional.h>

namespace LIEF::runtime::py {
template<>
void create<Process>(nb::module_& m) {
  nb::class_<Process> obj(m, "Process",
    R"doc(
    This class represents the current process and provides functions to query
    process-level information.
    )doc"_doc
  );

  nb::class_<Process::EnvVars>(obj, "EnvVars",
    R"doc(This structure wraps environment variables)doc"_doc
  )
    .def_rw("vars", &Process::EnvVars::vars)
  ;

  obj
    .def_prop_ro_static("pid", [] (nb::handle) {
      return Process::pid();
    }, "Get the Process ID of the current process."_doc)

    .def_prop_ro_static("tid", [] (nb::handle) {
      return Process::tid();
    }, "Get the Thread ID of the current thread."_doc)

    .def_prop_ro_static("arch", [] (nb::handle) {
      return Process::arch();
    }, "Return the target architecture of the current process."_doc)

    .def_prop_ro_static("page_size", [] (nb::handle) {
      return Process::page_size();
    }, R"doc(
    Return the number of bytes in a memory page.

    For instance:
    * ``0x1000`` (4096 bytes) for x86_64
    * ``0x4000`` (16384 bytes) for ARM64
    )doc"_doc)

    .def_prop_ro_static("platform", [] (nb::handle) {
      return Process::platform();
    }, "Return the target platform of the current process."_doc)

    .def_static("get_env", &Process::get_env,
      "Return the environment variable associated with the given key"_doc,
      "key"_a
    )

    .def_prop_ro_static("envs", [] (nb::handle) {
      return Process::get_envs();
    }, "Return the environment variables present in the current process"_doc)
  ;
}

}
