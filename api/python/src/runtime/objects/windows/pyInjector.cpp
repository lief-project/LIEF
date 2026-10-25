#include "LIEF/runtime/windows/injector.hpp"
#include "pyErr.hpp"
#include "pyLIEF.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unordered_map.h>
namespace LIEF::runtime::windows::py {

void init_injector(nb::module_& m) {
  nb::class_<injection_context_t>(
      m, "injection_context_t",
      "Describes how to spawn a new process and inject a library into it."_doc
  )
      .def(nb::init<>())
      .def_rw("target_path", &injection_context_t::target_path,
              "Absolute path to the target executable to spawn."_doc)
      .def_rw("args", &injection_context_t::args,
              "Command-line arguments passed to the spawned process."_doc)
      .def_rw("library", &injection_context_t::library,
              "Absolute path to the library (DLL) that should be injected."_doc)
      .def_rw("env", &injection_context_t::env,
              R"doc(
              Environment variables to set in the spawned process. If left empty,
              the current process environment is inherited.
              )doc"_doc);

  m.def(
      "inject_spawn",
      [](const injection_context_t& ctx) {
        return LIEF::py::error_or(&inject_spawn, ctx);
      },
      "ctx"_a,
      R"doc(
      Spawn the target described by the given injection context and inject the
      associated library before the main thread starts executing.
      )doc"_doc
  );
}

}
